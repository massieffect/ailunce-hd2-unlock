import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.util.*;

public class FindBeep3 extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    Memory mem=currentProgram.getMemory();
    ConsoleTaskMonitor mon=new ConsoleTaskMonitor();
    // 1) disassemble the code region as Thumb
    AddressSet set=new AddressSet(A(0x0300D000L+0x4000),A(0x0300D000L+0xb0000));
    ArmDisassembleCommand dis=new ArmDisassembleCommand(set,null,true); // thumb=true
    dis.applyTo(currentProgram,mon);
    println("disassembled. now creating functions at prologues...");
    // 2) find push{lr} / stmdb prologues and create functions
    int made=0;
    Listing lst=currentProgram.getListing();
    // helper: find function start by scanning back for push {..,lr}
    long[] anchors={0x0302a7d8L,0x03035cf8L};
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    for(long anc: anchors){
      Address entry=null;
      for(long a=anc; a> anc-0x800; a-=2){
        try{
          int hw=mem.getShort(A(a))&0xffff;
          if((hw&0xff00)==0xb500){ entry=A(a); break; }       // push {..,lr}
          if(hw==0xe92d){ entry=A(a); break; }                 // stmdb sp!,{..}
        }catch(Exception e){}
      }
      if(entry==null){ println("no prologue before "+Long.toHexString(anc)); continue; }
      CreateFunctionCmd cf=new CreateFunctionCmd(entry);
      cf.applyTo(currentProgram,mon);
      Function f=currentProgram.getFunctionManager().getFunctionAt(entry);
      println("\n==== function @"+entry+" (anchor "+Long.toHexString(anc)+") name="+(f!=null?f.getName():"?")+" ====");
      if(f!=null){
        // callers via references to entry
        ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(entry);
        println("CALLERS:");
        for(Reference r: ri){ if(r.getReferenceType().isCall()||r.getReferenceType().isFlow())
           println("   from "+r.getFromAddress()+" type="+r.getReferenceType()); }
        DecompileResults res=dec.decompileFunction(f,90,mon);
        if(res!=null&&res.getDecompiledFunction()!=null){
          String c=res.getDecompiledFunction().getC();
          println(c.length()>4000?c.substring(0,4000):c);
        }
      }
    }
  }
}
