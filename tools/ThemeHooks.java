// Two presentation-only hooks. Removing them must restore the entire canonical DEX.
import java.nio.file.*;
import java.util.*;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import com.android.tools.smali.dexlib2.iface.reference.*;
import com.android.tools.smali.dexlib2.builder.*;
import com.android.tools.smali.dexlib2.builder.instruction.*;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.rewriter.*;

public final class ThemeHooks {
    static final String PREFIX="Laxis/androidtv/sdk/app/template/pageentry/";
    static final Map<String,String> TARGETS=new LinkedHashMap<>();
    static{TARGETS.put(PREFIX+"hero/viewholder/H9ViewHolder;","header");TARGETS.put(PREFIX+"editorial/viewholder/Ed1ViewHolder;","promotion");}
    static DexFile transform(DexFile source,boolean reverse,int[] count){
        return new DexRewriter(new RewriterModule(){
            @Override public Rewriter<Method> getMethodRewriter(Rewriters rewriters){
                return method->{
                    String hook=TARGETS.get(method.getDefiningClass());
                    if(hook==null||!method.getName().equals("bindPageEntry")||!method.getParameterTypes().isEmpty()||!method.getReturnType().equals("V"))return method;
                    MethodImplementation original=method.getImplementation();
                    if(original==null||!original.getTryBlocks().isEmpty())throw new IllegalStateException("Unexpected binding body");
                    MutableMethodImplementation code=new MutableMethodImplementation(original);
                    int sites=0;
                    for(int i=code.getInstructions().size()-1;i>=0;i--){
                        Instruction instruction=code.getInstructions().get(i);
                        if(!reverse&&instruction.getOpcode()==Opcode.RETURN_VOID){
                            // Replace the labelled return itself so branches execute the hook too.
                            code.replaceInstruction(i,new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE,code.getRegisterCount()-1,1,
                                new ImmutableMethodReference("Lorg/drtvdark/watchdog/ThemeCorrections;",hook,Arrays.asList("Ljava/lang/Object;"),"V")));
                            code.addInstruction(i+1,new BuilderInstruction10x(Opcode.RETURN_VOID));sites++;
                        }else if(reverse&&instruction instanceof ReferenceInstruction){
                            Reference ref=((ReferenceInstruction)instruction).getReference();
                            if(ref instanceof MethodReference&&((MethodReference)ref).getDefiningClass().equals("Lorg/drtvdark/watchdog/ThemeCorrections;")){
                                if(!((MethodReference)ref).getName().equals(hook)||code.getInstructions().get(i+1).getOpcode()!=Opcode.RETURN_VOID)throw new IllegalStateException("Unexpected hook");
                                code.removeInstruction(i+1);code.replaceInstruction(i,new BuilderInstruction10x(Opcode.RETURN_VOID));sites++;
                            }
                        }
                    }
                    int expected=1;
                    if(sites!=expected)throw new IllegalStateException("Unexpected return/hook count: "+hook+" "+sites);
                    count[0]+=sites;
                    return new ImmutableMethod(method.getDefiningClass(),method.getName(),method.getParameters(),method.getReturnType(),method.getAccessFlags(),method.getAnnotations(),method.getHiddenApiRestrictions(),code);
                };
            }
        }).getDexFileRewriter().rewrite(source);
    }
    public static void main(String[] args)throws Exception{
        Path in=Path.of(args[0]),out=Path.of(args[1]);
        DexFile source=new DexBackedDexFile(null,Files.readAllBytes(in));int[] count={0};
        IdentityTransform.write(out,transform(source,false,count));
        if(count[0]!=2)throw new IllegalStateException("Two hook sites required");
        Path canonical=out.resolveSibling("theme-source-canonical.dex"),reverse=out.resolveSibling("theme-reverse-canonical.dex");
        IdentityTransform.write(canonical,source);count[0]=0;
        IdentityTransform.write(reverse,transform(new DexBackedDexFile(null,Files.readAllBytes(out)),true,count));
        if(count[0]!=2||!Arrays.equals(Files.readAllBytes(canonical),Files.readAllBytes(reverse)))throw new IllegalStateException("Unexpected DEX semantics outside hooks");
        System.out.println("PASS\t2 presentation hook sites; full canonical reverse equality");
    }
}
