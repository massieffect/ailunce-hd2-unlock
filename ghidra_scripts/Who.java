import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
public class Who extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    FunctionManager fm=currentProgram.getFunctionManager();
    Listing l=currentProgram.getListing();
    long handler=0x030359b0L;
    println("W> ===== all call sites to PlayBeep handler @0x30359b0, with beepType (r0) =====");
    for(Reference r: getReferencesTo(A(handler))){
      if(!r.getReferenceType().isCall()) continue;
      Address site=r.getFromAddress();
      Function from=fm.getFunctionContaining(site);
      // scan back up to 10 instrs for 'movi r0,imm' (beepType)
      String beep="?";
      long a=site.getOffset();
      for(int i=0;i<12;i++){
        a-=2; Instruction ins=l.getInstructionAt(A(a)); if(ins==null) continue;
        String s=ins.toString();
        if(s.startsWith("movi r0,")||s.startsWith("movi16 r0,")){ beep=s.substring(s.indexOf(',')+1); break; }
        if(ins.getMnemonicString().equals("push")) break;
      }
      println(String.format("  call@%s beepType(r0)=%-8s in %s", site, beep, from!=null?from.getName()+"@"+from.getEntryPoint():"?"));
    }
  }
}
