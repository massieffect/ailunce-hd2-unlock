import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.task.ConsoleTaskMonitor;
public class SeedProlog extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    Memory mem=currentProgram.getMemory();
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    long base=0x0300D000L;
    long start=base+0x4000, end=base+0x90000;
    int made=0;
    for(long a=start; a<end; a+=2){
      int hw;
      try{ hw=mem.getShort(A(a))&0xffff; }catch(Exception e){ continue; }
      boolean prologue=false;
      if((hw&0xff00)==0xb500) prologue=true;            // push {..,lr}
      else if(hw==0xe92d){                               // push.w {..,lr}
        int hw2; try{ hw2=mem.getShort(A(a+2))&0xffff; }catch(Exception e){ continue; }
        if((hw2&0x4000)!=0) prologue=true;               // includes lr
      }
      if(prologue){
        try{
          new ArmDisassembleCommand(A(a),null,true).applyTo(currentProgram,mon);
          new CreateFunctionCmd(A(a)).applyTo(currentProgram,mon);
          made++;
        }catch(Exception e){}
      }
    }
    println("SEEDP> created ~"+made+" functions from prologues");
  }
}
