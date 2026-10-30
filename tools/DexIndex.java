// Read-only instruction indexing with the dexlib bundled in the existing Apktool JAR.
// Never rebuilds a DEX or a resource table.
import java.nio.file.*;
import java.util.*;
import com.android.tools.smali.dexlib2.dexbacked.*;
import com.android.tools.smali.dexlib2.dexbacked.instruction.DexBackedInstruction;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;

public class DexIndex {
    public static void main(String[] args) throws Exception {
        byte[] bytes = Files.readAllBytes(Path.of(args[0]));
        DexBackedDexFile dex = new DexBackedDexFile(bytes, 0);
        Set<String> targets = new HashSet<>(Arrays.asList(args).subList(1, args.length));
        boolean verify = targets.contains("--verify");
        int checked = 0;
        for (Object co : dex.classSection) {
            DexBackedClassDef cls = (DexBackedClassDef) co;
            List<Object> methods = new ArrayList<>();
            for (Object m : cls.getDirectMethods()) methods.add(m);
            for (Object m : cls.getVirtualMethods()) methods.add(m);
            for (Object mo : methods) {
                DexBackedMethod method = (DexBackedMethod) mo;
                StringBuilder signature = new StringBuilder(cls.getType()).append("->").append(method.getName()).append("(");
                for (Object type : method.getParameterTypes()) signature.append(type);
                signature.append(")").append(method.getReturnType());
                boolean selected = targets.contains(signature.toString());
                if (!verify && !selected) continue;
                DexBackedMethodImplementation impl = (DexBackedMethodImplementation) method.getImplementation();
                if (impl == null) continue;
                int units = 0;
                List<String> instructions = new ArrayList<>();
                for (Object io : impl.getInstructions()) {
                    DexBackedInstruction insn = (DexBackedInstruction) io;
                    if (insn.getCodeUnits() <= 0) throw new IllegalStateException("Invalid instruction width");
                    if (verify && insn instanceof ReferenceInstruction) ((ReferenceInstruction) insn).getReference().toString();
                    String reference = "-";
                    if (selected && insn instanceof ReferenceInstruction && ((ReferenceInstruction) insn).getReference() instanceof MethodReference)
                        reference = ((ReferenceInstruction) insn).getReference().toString();
                    if (selected) instructions.add("I\t" + insn.instructionStart + "\t" + insn.getOpcode().name + "\t" + insn.getCodeUnits() + "\t" +
                        (insn instanceof NarrowLiteralInstruction ? Integer.toUnsignedString(((NarrowLiteralInstruction) insn).getNarrowLiteral()) : "-") + "\t" + reference);
                    units += insn.getCodeUnits();
                }
                if (impl.codeOffset + 16L + units * 2L > bytes.length) throw new IllegalStateException("Code out of bounds");
                for (Object t : impl.getTryBlocks()) t.toString();
                checked++;
                if (selected) {
                    System.out.println("M\t" + signature + "\t" + impl.codeOffset + "\t" + units + "\t" + impl.getTryBlocks().size() + "\t" + method.methodIndex);
                    for (String line : instructions) System.out.println(line);
                }
            }
        }
        if (verify) System.out.println("VERIFIED\t" + checked);
    }
}
