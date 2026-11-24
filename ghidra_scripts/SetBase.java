import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
public class SetBase extends GhidraScript {
  public void run() throws Exception {
    Address nb=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x0300D000L);
    int tx=currentProgram.startTransaction("rebase");
    currentProgram.setImageBase(nb, true);
    currentProgram.endTransaction(tx,true);
    println("SB> image base set to "+currentProgram.getImageBase());
  }
}
