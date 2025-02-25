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

  kp,err := link.Kprobe("sys_open", objs.HandleOpen, nil)

  if err != nil {
    log.Fatal("Error opening kprobe : %v",err)
  }
  defer kp.Close()

  rd,err := ringbuf.NewReader(objs.Events)

  if err != nil {
    log.Fatalf("Error open ring buffer : %v", err) 
  }
  defer rd.Close()
  
  go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()
  
  log.Println("Waiting for events..")

  var events ebpfFileEvent
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

    log.Printf("PID: %d | UID: %d | Comm: %s | Filename: %s | Flags: %d | Timestamp: %d\n",
      events.Pid,events.Uid,unix.ByteSliceToString(events.Comm[:]),unix.ByteSliceToString(events.Filename[:]),events.Flags,events.TimestampNs)
  }
} 


















