package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type file_event ebpf file_logger.bpf.c


func main(){
  log.SetPrefix("file_ebpf: ")
  log.SetFlags(log.Ltime)

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
  
  log.Println("Waiting for events..")
  
  var events ebpfFileEvent
  var rw_events ebpfRwEvent
  for{
    record,err := rd.Read()

    if err != nil {
      if errors.Is(err, ringbuf.ErrClosed){
        log.Println("Received signal, exiting...")
        return
      }

      log.Printf("Reading from reader: %s", err)
      continue
    }

    if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &events); err!=nil{
      log.Printf("parsing ringbuf event: %s", err)
      continue
    }
    
    log.Printf(" Openat syscall log :PID: %d | UID: %d | Comm: %s | Filename: %s | Flags: %d | Timestamp: %d | Timestamp exit: %d | ret: %d | Latency: %d\n",
    events.Pid,events.Uid,unix.ByteSliceToString(events.Comm[:]),unix.ByteSliceToString(events.Filename[:]),events.Flags,events.TimestampNs,
    events.TimestampNsExit,events.Ret,events.Latency)
    
    record2,err := rd2.Read()

    if err != nil {
      if errors.Is(err, ringbuf.ErrClosed){
        log.Println("Received signal, exiting...")
        return
      }

      log.Printf("Reading from reader: %s", err)
      continue
    }

    if err := binary.Read(bytes.NewBuffer(record2.RawSample), binary.LittleEndian, &rw_events); err!=nil{
      log.Printf("parsing ringbuf event: %s", err)
      continue
    }
    
    if rw_events.SyscallType == 0{
      log.Printf("read syscall log :PID: %d | UID: %d | Comm: %s | fd: %d | count: %d | Timestamp: %d | Timestamp exit: %d | ret: %d | Latency: %d\n",
    rw_events.Pid,rw_events.Uid,unix.ByteSliceToString(rw_events.Comm[:]),rw_events.Fd,rw_events.Count,rw_events.TimestampNs,
    rw_events.TimestampNsExit,rw_events.Ret,rw_events.Latency)
    }else{
    
      log.Printf("write syscall log :PID: %d | UID: %d | Comm: %s | fd: %d | count: %d | Timestamp: %d | Timestamp exit: %d | ret: %d | Latency: %d\n",
    rw_events.Pid,rw_events.Uid,unix.ByteSliceToString(rw_events.Comm[:]),rw_events.Fd,rw_events.Count,rw_events.TimestampNs,
    rw_events.TimestampNsExit,rw_events.Ret,rw_events.Latency)
    
    }
    
  }
} 


















