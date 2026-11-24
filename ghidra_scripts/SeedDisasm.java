import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.util.task.ConsoleTaskMonitor;
public class SeedDisasm extends GhidraScript {
  Address A(long v){ return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v); }
  public void run() throws Exception {
    AddressSet set=new AddressSet(A(0x0300D000L+0x4000), A(0x0300D000L+0x90000));
    new ArmDisassembleCommand(set,null,true).applyTo(currentProgram,new ConsoleTaskMonitor());
    println("SEED> disassembled code region, letting analysis find functions");
  }
}
