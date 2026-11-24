import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
public class QualCheck extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    // DMR Mode string va 0x030ABF60 ; its pointer is at file 0x5657c (va 0x0306357C)
    // decompile the function containing the LDR near 0x0306357C
    for(long probe : new long[]{0x0306357CL, 0x03063560L, 0x0306354cL}){
      Function f=fm.getFunctionContaining(A(probe));
      if(f!=null){
        println("QC> probe 0x"+Long.toHexString(probe)+" in FUNC "+f.getName()+"@"+f.getEntryPoint());
        DecompileResults r=dec.decompileFunction(f,60,mon);
        if(r!=null&&r.getDecompiledFunction()!=null){
          String c=r.getDecompiledFunction().getC();
          println(c.length()>2500?c.substring(0,2500):c);
        }
        return;
      }
    }
    println("QC> no function around the DMR Mode reference");
  }
}
