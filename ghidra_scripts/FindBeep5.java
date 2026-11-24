import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindBeep5 extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    Memory mem=currentProgram.getMemory();
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    long[] anchors={0x03035cf8L, 0x0302a7d8L};
    String[] lbl={"DISPATCHER","Hal_BeepPlay"};
    for(int k=0;k<anchors.length;k++){
      long anc=anchors[k];
      // find prologue before anchor
      long entry=-1;
      for(long a=anc; a>anc-0x1200; a-=2){
        int hw=mem.getShort(A(a))&0xffff;
        if((hw&0xff00)==0xb500 || hw==0xe92d){ entry=a; break; }
      }
      if(entry<0){ println("B5> "+lbl[k]+": no prologue"); continue; }
      // disassemble a function-sized window from entry
      AddressSet set=new AddressSet(A(entry), A(anc+0x1200));
      new ArmDisassembleCommand(set,null,true).applyTo(currentProgram,mon);
      new CreateFunctionCmd(A(entry)).applyTo(currentProgram,mon);
      Function f=currentProgram.getFunctionManager().getFunctionAt(A(entry));
      println("B5> ######## "+lbl[k]+" entry=0x"+Long.toHexString(entry)+" func="+(f!=null?f.getName():"null")+" ########");
      if(f!=null){
        DecompileResults res=dec.decompileFunction(f,120,mon);
        if(res!=null&&res.getDecompiledFunction()!=null){
          for(String line: res.getDecompiledFunction().getC().split("\n")) println("B5> "+line);
        } else println("B5> decompile failed: "+(res!=null?res.getErrorMessage():"null"));
      }
    }
  }
}
