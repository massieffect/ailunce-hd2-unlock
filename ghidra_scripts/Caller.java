import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
public class Caller extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    Listing l=currentProgram.getListing();
    // function entry for the wrapper containing 0x03035c12
    long entry=-1;
    for(long a=0x03035c12L;a>0x03035a00L;a-=2){ Instruction ins=l.getInstructionAt(A(a));
      if(ins!=null && ins.getMnemonicString().equals("push")){ entry=a; break; } }
    println("C> wrapper entry: 0x"+Long.toHexString(entry));
    Function wf=fm.getFunctionContaining(A(0x03035c12L));
    if(wf==null && entry>0){ new CreateFunctionCmd(A(entry)).applyTo(currentProgram,mon); wf=fm.getFunctionContaining(A(0x03035c12L)); }
    println("C> wrapper = "+(wf!=null?wf.getName()+"@"+wf.getEntryPoint():"?"));
    // disasm around the dispatcher call
    println("C> ===== disasm 0x03035bf0-0x03035c20 (beepType arg) =====");
    for(long a=0x03035bf0L;a<0x03035c20L;){ Instruction ins=l.getInstructionAt(A(a)); if(ins==null){a+=2;continue;}
      println(String.format("   %08x  %s",a,ins.toString())); a+=ins.getLength(); }
    if(wf!=null){
      println("C> ===== callers of wrapper (each passes a beepType) =====");
      for(Function c: wf.getCallingFunctions(mon)){
        StringBuilder up=new StringBuilder();
        for(Function cc: c.getCallingFunctions(mon)) up.append(cc.getName()+" ");
        println("  "+c.getName()+"@"+c.getEntryPoint()+"  <- "+up);
      }
    }
  }
}
