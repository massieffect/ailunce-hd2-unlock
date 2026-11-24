import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
public class Dump extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    Listing l=currentProgram.getListing();
    long start=0x03015500L, end=0x030156a0L;
    for(long a=start;a<end;){
      Instruction ins=l.getInstructionAt(A(a));
      if(ins==null){ Data dd=l.getDataAt(A(a)); println(String.format("   %08x  <data> %s",a, dd!=null?dd.toString():"?")); a+=2; continue; }
      String ref="";
      for(Reference r: ins.getReferencesFrom()){
        ref+=" ->"+r.getToAddress();
        ghidra.program.model.listing.Function tf=currentProgram.getFunctionManager().getFunctionAt(r.getToAddress());
        if(tf!=null) ref+="("+tf.getName()+")";
      }
      println(String.format("   %08x  %-26s%s",a, ins.toString(), ref));
      a+=ins.getLength();
    }
  }
}
