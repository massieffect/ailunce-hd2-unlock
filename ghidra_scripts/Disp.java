import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;
public class Disp extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    // find dispatcher entry: scan back from 0x03015500 for push
    Listing l=currentProgram.getListing();
    long entry=-1;
    for(long a=0x03015500L;a>0x03015380L;a-=2){
      Instruction ins=l.getInstructionAt(A(a));
      if(ins!=null && ins.getMnemonicString().equals("push")){ entry=a; break; }
    }
    println("DP> dispatcher entry candidate: 0x"+Long.toHexString(entry));
    Function disp=fm.getFunctionContaining(A(0x03015500L));
    if(disp==null && entry>0){ new CreateFunctionCmd(A(entry)).applyTo(currentProgram,mon); disp=fm.getFunctionContaining(A(0x03015500L)); }
    if(disp==null){ println("DP> no dispatcher function"); return; }
    println("DP> dispatcher = "+disp.getName()+"@"+disp.getEntryPoint());
    println("DP> ===== CALLERS of dispatcher (who requests beeps) =====");
    for(Function c: disp.getCallingFunctions(mon)){
      // show the call site + the beepType arg if a 'movi rX, imm' precedes the call
      StringBuilder up=new StringBuilder();
      for(Function cc: c.getCallingFunctions(mon)) up.append(cc.getName()+"@"+cc.getEntryPoint()+" ");
      println("  "+c.getName()+"@"+c.getEntryPoint()+"   <-(callers) "+up);
    }
    // Also data refs (indirect/table callers)
    println("DP> ===== data/indirect refs to dispatcher entry =====");
    for(Reference r: getReferencesTo(disp.getEntryPoint())){
      Function from=fm.getFunctionContaining(r.getFromAddress());
      println("  "+r.getReferenceType()+" from "+r.getFromAddress()+" in "+(from!=null?from.getName()+"@"+from.getEntryPoint():"table/data"));
    }
  }
}
