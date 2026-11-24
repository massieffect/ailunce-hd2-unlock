import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;
public class Up extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  Function ensureFn(long addr){
    FunctionManager fm=currentProgram.getFunctionManager();
    Function f=fm.getFunctionContaining(A(addr));
    if(f!=null) return f;
    // scan back for push {..} prologue (C-SKY: 0x..e0 for push? use listing: find 'push' instr)
    long p=addr;
    Listing l=currentProgram.getListing();
    for(int i=0;i<0x400;i+=2){
      Instruction ins=l.getInstructionAt(A(addr-i));
      if(ins!=null && ins.getMnemonicString().equals("push")){ 
        new CreateFunctionCmd(A(addr-i)).applyTo(currentProgram,new ConsoleTaskMonitor());
        return fm.getFunctionContaining(A(addr));
      }
    }
    new CreateFunctionCmd(A(addr)).applyTo(currentProgram,new ConsoleTaskMonitor());
    return fm.getFunctionAt(A(addr));
  }
  void callers(Function f,String ind,int depth){
    if(f==null||depth<=0) return;
    FunctionManager fm=currentProgram.getFunctionManager();
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    for(Function c: f.getCallingFunctions(mon)){
      println(ind+c.getName()+"@"+c.getEntryPoint());
      callers(c,ind+"  ",depth-1);
    }
    // also data refs (pointer table callers)
    for(Reference r: getReferencesTo(f.getEntryPoint())){
      Function from=fm.getFunctionContaining(r.getFromAddress());
      if(from!=null && from!=f) { }
    }
  }
  public void run() throws Exception {
    Function seq1=ensureFn(0x030155aaL);
    Function seq2=ensureFn(0x03035c12L);
    println("U> seq-player1 = "+(seq1!=null?seq1.getName()+"@"+seq1.getEntryPoint():"?"));
    println("U> seq-player2 = "+(seq2!=null?seq2.getName()+"@"+seq2.getEntryPoint():"?"));
    println("\nU> ===== caller tree of seq-player1 (3 levels up) =====");
    callers(seq1,"  ",3);
    println("\nU> ===== caller tree of seq-player2 (3 levels up) =====");
    callers(seq2,"  ",3);
  }
}
