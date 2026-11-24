import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
public class Handler extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    Listing l=currentProgram.getListing();
    long entry=-1;
    for(long a=0x03035c12L;a>0x03035600L;a-=2){ Instruction ins=l.getInstructionAt(A(a));
      if(ins!=null && ins.getMnemonicString().equals("push")){ entry=a; } }
    // last push found scanning down is earliest; but we want the nearest-enclosing. redo: first push going up
    entry=-1;
    for(long a=0x03035c12L;a>0x03035600L;a-=2){ Instruction ins=l.getInstructionAt(A(a));
      if(ins!=null && ins.getMnemonicString().equals("push")){ entry=a; break; } }
    println("H> handler entry: 0x"+Long.toHexString(entry));
    Function hf=fm.getFunctionContaining(A(0x03035c12L));
    if(hf==null && entry>0){ new CreateFunctionCmd(A(entry)).applyTo(currentProgram,mon); hf=fm.getFunctionContaining(A(0x03035c12L)); }
    if(hf==null){ println("H> none - dumping raw around entry"); 
      for(long a=entry>0?entry:0x03035a00L;a<0x03035a40L;){Instruction ins=l.getInstructionAt(A(a));if(ins==null){a+=2;continue;}println(String.format("   %08x %s",a,ins.toString()));a+=ins.getLength();}
      return; }
    println("H> handler = "+hf.getName()+"@"+hf.getEntryPoint());
    println("H> ===== CALLERS of handler =====");
    for(Function c: hf.getCallingFunctions(mon)){
      StringBuilder up=new StringBuilder();
      for(Function cc: c.getCallingFunctions(mon)) up.append(cc.getName()+"@"+cc.getEntryPoint()+" ");
      println("  "+c.getName()+"@"+c.getEntryPoint()+"  <- "+up);
    }
    println("H> ===== first 30 instrs of handler (switch var) =====");
    int n=0; InstructionIterator it=l.getInstructions(hf.getBody(),true);
    while(it.hasNext()&&n<30){Instruction ins=it.next();println(String.format("   %08x %s",ins.getAddress().getOffset(),ins.toString()));n++;}
  }
}
