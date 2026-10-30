// Isolated development experiment. Rewrites four audited string constants only.
// No class/type namespace, auth, DRM, TLS or instruction behavior is rewritten.
import java.nio.file.*;
import java.util.*;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import com.android.tools.smali.dexlib2.iface.instruction.formats.*;
import com.android.tools.smali.dexlib2.iface.reference.*;
import com.android.tools.smali.dexlib2.iface.value.*;
import com.android.tools.smali.dexlib2.immutable.instruction.*;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.immutable.value.ImmutableStringEncodedValue;
import com.android.tools.smali.dexlib2.rewriter.*;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

public final class IdentityTransform {
    static void write(Path path,DexFile dex)throws Exception {
        SortedSet<ClassDef> classes=new TreeSet<>(Comparator.comparing(ClassDef::getType));
        classes.addAll(dex.getClasses());
        DexPool.writeTo(path.toString(),new DexFile() {
            public Set<? extends ClassDef> getClasses(){return classes;}
            public com.android.tools.smali.dexlib2.Opcodes getOpcodes(){return dex.getOpcodes();}
        });
    }
    static Map<String,String> mapping(String target) {
        String source="dk.dr.tvplayer", suffix=".templates.page.search.SearchSuggestionsProvider";
        Map<String,String> m=new LinkedHashMap<>();
        m.put(source,target);
        m.put(source+suffix,target+suffix);
        m.put("content://"+source+suffix+"/suggestions","content://"+target+suffix+"/suggestions");
        m.put("content://"+source+suffix+"/search_suggest_query","content://"+target+suffix+"/search_suggest_query");
        return m;
    }
    static DexFile rewrite(DexFile dex,Map<String,String> m) {
        return new DexRewriter(new RewriterModule() {
            @Override public Rewriter<Instruction> getInstructionRewriter(Rewriters r) {
                InstructionRewriter fallback=new InstructionRewriter(r);
                return instruction -> {
                    if(instruction instanceof ReferenceInstruction) {
                        Reference ref=((ReferenceInstruction)instruction).getReference();
                        if(ref instanceof StringReference) {
                            String replacement=m.get(((StringReference)ref).getString());
                            if(replacement!=null) {
                                ImmutableStringReference value=new ImmutableStringReference(replacement);
                                if(instruction instanceof Instruction21c)
                                    return new ImmutableInstruction21c(instruction.getOpcode(),((Instruction21c)instruction).getRegisterA(),value);
                                if(instruction instanceof Instruction31c)
                                    return new ImmutableInstruction31c(instruction.getOpcode(),((Instruction31c)instruction).getRegisterA(),value);
                                throw new IllegalStateException("Unsupported string instruction");
                            }
                        }
                    }
                    return fallback.rewrite(instruction);
                };
            }
            @Override public Rewriter<EncodedValue> getEncodedValueRewriter(Rewriters r) {
                EncodedValueRewriter fallback=new EncodedValueRewriter(r);
                return value -> {
                    if(value instanceof StringEncodedValue) {
                        String replacement=m.get(((StringEncodedValue)value).getValue());
                        if(replacement!=null)return new ImmutableStringEncodedValue(replacement);
                    }
                    return fallback.rewrite(value);
                };
            }
        }).getDexFileRewriter().rewrite(dex);
    }
    public static void main(String[] args)throws Exception {
        Path input=Path.of(args[0]),out=Path.of(args[1]);
        String target=args[2];
        if(!target.equals("io.github.nobewayo.drtvdark"))throw new IllegalArgumentException("B12 candidate only");
        Map<String,String> m=mapping(target);
        if(args.length==4&&args[3].equals("--isolate-links"))
            m.put("tvrecommendation://app",target+".recommendation://app");
        DexBackedDexFile source=new DexBackedDexFile(null,Files.readAllBytes(input));
        Set<String> found=new HashSet<>();
        for(StringReference s:source.getStringReferences())if(m.containsKey(s.getString()))found.add(s.getString());
        if(!found.equals(m.keySet()))throw new IllegalStateException("Exact approved original constants required");
        // Print only audited public identity owners, never proprietary method bodies.
        for(ClassDef cls:source.getClasses()) {
            for(Field field:cls.getFields())if(field.getInitialValue() instanceof StringEncodedValue) {
                String s=((StringEncodedValue)field.getInitialValue()).getValue();
                if(m.containsKey(s))System.out.println("FIELD\t"+field+"\t"+s);
            }
            for(Method method:cls.getMethods())if(method.getImplementation()!=null) {
                for(Instruction i:method.getImplementation().getInstructions())if(i instanceof ReferenceInstruction) {
                    Reference ref=((ReferenceInstruction)i).getReference();
                    if(ref instanceof StringReference&&m.containsKey(((StringReference)ref).getString()))
                        System.out.println("INSTRUCTION\t"+method+"\t"+((StringReference)ref).getString());
                }
            }
        }
        write(out,rewrite(source,m));
        // Lossless reverse semantic round trip via canonical dexlib serialization.
        Path canonical=out.resolveSibling(out.getFileName()+"-source-canonical.dex"),roundtrip=out.resolveSibling(out.getFileName()+"-reverse-canonical.dex");
        write(canonical,source);
        Map<String,String> reverse=new LinkedHashMap<>();m.forEach((k,v)->reverse.put(v,k));
        DexBackedDexFile changed=new DexBackedDexFile(null,Files.readAllBytes(out));
        write(roundtrip,rewrite(changed,reverse));
        if(!Arrays.equals(Files.readAllBytes(canonical),Files.readAllBytes(roundtrip)))
            throw new IllegalStateException("Unexpected DEX semantic/structural change after reverse mapping");
        System.out.println("PASS\t"+m.size()+" exact string constants; all other serialized DEX semantics unchanged");
    }
}
