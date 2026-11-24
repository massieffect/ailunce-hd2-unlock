import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindBeep4 extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    println(">>> total functions now: "+fm.getFunctionCount());
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    long[] anchors={0x03035cf8L, 0x0302a7d8L};
    String[] lbl={"DISPATCHER(beepType)","Hal_BeepPlay"};
    for(int k=0;k<anchors.length;k++){
      Function f=fm.getFunctionContaining(A(anchors[k]));
      println("\n############ "+lbl[k]+" anchor=0x"+Long.toHexString(anchors[k])+" ############");
      if(f==null){ println("NO FUNCTION containing anchor"); continue; }
      println("FUNC "+f.getName()+" @"+f.getEntryPoint());
      // callers
      println("-- CALLERS --");
      ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
      int cc=0;
      for(Reference r: ri){ if(r.getReferenceType().isCall()){ cc++;
        Function cf=fm.getFunctionContaining(r.getFromAddress());
        println("   called from "+r.getFromAddress()+" in "+(cf!=null?cf.getName()+"@"+cf.getEntryPoint():"?")); } }
      if(cc==0) println("   (no call refs)");
      DecompileResults res=dec.decompileFunction(f,120,mon);
      if(res!=null&&res.getDecompiledFunction()!=null){
        println("-- DECOMPILE --");
        String c=res.getDecompiledFunction().getC();
        println(c.length()>5000?c.substring(0,5000):c);
      }
    }
  }
}
