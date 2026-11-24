import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
public class Table extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    Memory mem=currentProgram.getMemory();
    Listing l=currentProgram.getListing();
    long tbl=0x0309977cL;
    println("T> ===== beepType jump table @0x0309977c (20 entries) =====");
    for(int i=0;i<20;i++){
      long e=mem.getInt(A(tbl+i*4))&0xffffffffL;
      // dump first ~8 instrs of the case to see the tone played (freq consts)
      StringBuilder sb=new StringBuilder();
      long a=e; int c=0;
      while(c<10){ Instruction ins=l.getInstructionAt(A(a)); if(ins==null) break;
        String s=ins.toString();
        if(s.startsWith("movi r0,")||s.startsWith("movi r1,")||s.contains("bsr")) sb.append(s+" | ");
        if(ins.getMnemonicString().equals("br")||ins.getMnemonicString().equals("rts")) break;
        a+=ins.getLength(); c++; }
      println(String.format("  case[%2d] (beepType %2d) -> 0x%08x :  %s", i, i+0xc, e, sb.toString()));
    }
  }
}
