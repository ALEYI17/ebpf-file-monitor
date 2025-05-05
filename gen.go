package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type file_event ebpf file_logger.bpf.c


func main(){

  logger:= setupLogger()

  stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

  if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

  objs := ebpfObjects{}
  if err := loadEbpfObjects(&objs,nil); err != nil{
    log.Fatalf("Error loading obj : %v",err)
  }
  defer objs.Close()
  
  // For openat 
  kpr,err := link.Tracepoint("syscalls","sys_exit_openat",objs.HandleExitOpenatTpbtf,nil)
  if err != nil {
    log.Fatal("Error opening tracepoint for openat exit: %v",err)
  }
  defer kpr.Close()

  kp,err := link.Tracepoint("syscalls","sys_enter_openat", objs.HandleOpenatTcbtf, nil)
  if err != nil {
    log.Fatal("Error opening tracepoint for openat enter : %v",err)
  }
  defer kp.Close()
  
  rd,err := ringbuf.NewReader(objs.Events)

  if err != nil {
    log.Fatalf("Error open ring buffer : %v", err) 
  }
  defer rd.Close()

  // For Read 
  kp2,err := link.Tracepoint("syscalls","sys_enter_read", objs.HandleEnterRead, nil)
  if err != nil {
    log.Fatal("Error opening tracepoint for read enter: %v",err)
  }
  defer kp2.Close()
  
  kpr2,err := link.Tracepoint("syscalls","sys_exit_read",objs.HandleExitRead,nil)
  if err != nil {
    log.Fatal("Error opening tracepoint for read exit: %v",err)
  }
  defer kpr2.Close()
  
  // For write 
  kp3,err := link.Tracepoint("syscalls","sys_enter_write", objs.HandleEnterWrite, nil)
  if err != nil {
    log.Fatal("Error opening tracepoint for write enter: %v",err)
  }
  defer kp3.Close()
  
  kpr3,err := link.Tracepoint("syscalls","sys_exit_write",objs.HandleExitWrite,nil)
  if err != nil {
    log.Fatal("Error opening tracepoint for write exit: %v",err)
  }
  defer kpr3.Close()
  
  rd2,err := ringbuf.NewReader(objs.RbRw)

  if err != nil {
    log.Fatalf("Error open ring buffer rw: %v", err) 
  }
  defer rd2.Close()


  go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
    if err := rd.Close();err != nil{
      log.Fatalf("Closing ringbuf reader: %s", err)
    }
	}()
  
  logger.Info("Waiting for events..")
  
  var events ebpfFileEvent
  var rw_events ebpfRwEvent
  for{
    record,err := rd.Read()

    if err != nil {
      if errors.Is(err, ringbuf.ErrClosed){
        logger.Printf("Received signal, exiting...")
        return
      }

      logger.Printf("Reading from reader: %s", err)
      continue
    }

    if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &events); err!=nil{
      logger.Printf("parsing ringbuf event: %s", err)
      continue
    }
    
    logOpenat(logger, events)

    record2,err := rd2.Read()

    if err != nil {
      if errors.Is(err, ringbuf.ErrClosed){
        logger.Infof("Received signal, exiting...")
        return
      }

      logger.Printf("Reading from reader: %s", err)
      continue
    }

    if err := binary.Read(bytes.NewBuffer(record2.RawSample), binary.LittleEndian, &rw_events); err!=nil{
      logger.Infof("parsing ringbuf event: %s", err)
      continue
    }
    
    if rw_events.SyscallType == 0{
      logReadWrite(logger, "read", rw_events)
    }else{
      logReadWrite(logger, "write", rw_events)
    }
    
  }
} 


// setupLogger initializes the logger with custom styles
func setupLogger() *log.Logger {
	logger := log.New(os.Stdout) // Output logs to the console

	// Define styles
	styles := log.DefaultStyles()
  
  // Set uniform styling for all keys and values
	keyColor := lipgloss.Color("196")   // Bright Yellow
	valueColor := lipgloss.Color("250")  // Bright Blue

	keys := []string{
		"syscall", "pid", "uid", "command", "filename", "flags", "timestamp",
		"return", "latency_ns", "fd", "count",
	}

	for _, key := range keys {
		styles.Keys[key] = lipgloss.NewStyle().Foreground(keyColor).Bold(true)
		styles.Values[key] = lipgloss.NewStyle().Foreground(valueColor).Bold(true)
	}

  // Apply styles to the logger
	logger.SetStyles(styles)
	logger.SetLevel(log.DebugLevel)       // Show debug, info, warn, and error logs
	logger.SetTimeFormat(time.RFC3339)    // ISO format timestamp
	logger.SetReportTimestamp(true)       // Include timestamps
	return logger
}

func logOpenat(logger *log.Logger, event ebpfFileEvent) {
	logger.Info("Openat syscall",
		"syscall", "openat",
		"pid", event.Pid,
		"ppid", event.Ppid,
		"uid", event.Uid,
		"gid", event.Gid,
		"user_pid", event.UserPid,
		"user_ppid", event.UserPpid,
		"cgroup_id", event.CgroupId,
		"cgroup_name", unix.ByteSliceToString(event.CgroupName[:]),
		"command", unix.ByteSliceToString(event.Comm[:]),
		"filename", unix.ByteSliceToString(event.Filename[:]),
		"flags", event.Flags,
		"timestamp", event.TimestampNs,
		"return", event.Ret,
		"latency_ns", event.Latency,
		"timestamp_exit", event.TimestampNsExit,
	)
}
func logReadWrite(logger *log.Logger, syscallType string, event ebpfRwEvent) {
	logger.Info("Read/Write syscall",
		"syscall", syscallType,
		"pid", event.Pid,
		"uid", event.Uid,
		"command", unix.ByteSliceToString(event.Comm[:]),
		"fd", event.Fd,
		"count", event.Count,
		"timestamp", event.TimestampNs,
		"return", event.Ret,
		"latency_ns", event.Latency,
	)
}












