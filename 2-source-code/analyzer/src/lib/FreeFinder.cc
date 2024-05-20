#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/TypeFinder.h>
#include <llvm/Pass.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/raw_ostream.h>

#include "FreeFinder.h"

using namespace llvm;
using namespace std;

bool FreeFinderPass::doInitialization(Module *M) { return false; }

bool FreeFinderPass::doFinalization(Module *M) { return false; }

bool FreeFinderPass::doModulePass(Module *M) {
  for (auto &Fx : *M) {
    for (auto &BB : Fx) {
      for (auto &II : BB) {
        Instruction *I = &II;
        

        if (auto CI = dyn_cast<CallInst>(I)) {
          Function *F = CI->getCalledFunction();
          if (!F)
            continue;
          if (freeAPIVec.find(F->getName()) != freeAPIVec.end()) {
            
            Value *freeArg = cast<Value>(CI->getOperand(0));
            if (F->getName() == "kmem_cache_free") {
              freeArg = cast<Value>(CI->getOperand(1));
            }

            if (auto *BCI = dyn_cast<BitCastInst>(freeArg)) {
              StringRef name = handleType(BCI->getSrcTy());
              if (name == targetSt) {
                // KA_LOGS(0, "Got name " << name << "\n");
                // KA_LOGS(0, "Found Bitcast :" << *BCI << "\n");
                Ctx->Frees.insert(CI);
                continue;
              }
            }

            if (auto *GEI = dyn_cast<GetElementPtrInst>(freeArg)) {
              // this is for kfree_rcu
              StringRef name = handleType(GEI->getPointerOperandType());
              if (name == targetSt) {
                // KA_LOGS(0, "Got name " << name << "\n");
                // KA_LOGS(0, "Found Bitcast :" << *BCI << "\n");
                Ctx->Frees.insert(CI);
                continue;
              }
            }

            if (auto *LI = dyn_cast<LoadInst>(freeArg)) {
              // this is for cases similar to vfs_cap_data
              for (auto *user1 : LI->getOperand(0)->users()) {
                for (auto *user2 : user1->users()) {
                  if (auto *BCI = dyn_cast<BitCastInst>(user2)) {
                    StringRef name = handleType(BCI->getDestTy());
                    if (name == targetSt) {
                      // KA_LOGS(0, "Got name " << name << "\n");
                      // KA_LOGS(0, "Found Bitcast :" << *BCI << "\n");
                      Ctx->Frees.insert(CI);
                    }
                  }
                }
              continue;
              }
            }

            for (auto *user : freeArg->users()) {
              if (auto *SI = dyn_cast<StoreInst>(user)) {
                
              } else if (auto *BCI = dyn_cast<BitCastInst>(user)) {
                StringRef name = handleType(BCI->getDestTy());
                if (name == targetSt) {
                  // KA_LOGS(0, "Got name " << name << "\n");
                  // KA_LOGS(0, "Found Bitcast :" << *BCI << "\n");
                  Ctx->Frees.insert(CI);
                }
              }
            }
          }
        }
      }
    }
  }

  return false;
}

void FreeFinderPass::dump() {
  KA_LOGS(0, "dumping location of freeing " << targetSt);

  if (targetSt == "sk_buff") {
    KA_LOGS(0, "kfree_skb");
    return;
  }

  for (auto CI : Ctx->Frees) {
    // log the src information
    DILocation *Loc = CI->getDebugLoc();
    Function *F = CI->getFunction();

    if (!Loc || !F || !F->hasName())
      continue;
    StringRef sourceF = Loc->getScope()->getFilename();
    if (sourceF.startswith("./")) {
      sourceF = sourceF.split("./").second;
    }
    KA_LOGS(0, F->getName() << " " << sourceF + ":" << Loc->getLine());
    KA_LOGS(0, "Possible Caller for " << F->getName());
    CallInstSet CIS = Ctx->Callers[F];
    for (auto C : CIS) {
	Function *CF = C->getFunction();
	if (!CF || !CF->hasName())
	    continue;
        KA_LOGS(0, CF->getName());
    }
    KA_LOGS(0, "");
  }
}

StringRef FreeFinderPass::handleType(Type *ty) {

  if (ty == nullptr)
    return StringRef("");

    // debug type
#if 0
    std::string type_str;
    llvm::raw_string_ostream rso(type_str);
    ty->print(rso);
    KA_LOGS(0, "type :" << rso.str());
#endif

  if (ty->isStructTy()) {
    StructType *ST = dyn_cast<StructType>(ty);
    StringRef stname = ST->getName();

    if (stname.startswith("struct.") && !stname.startswith("struct.anon"))
      return stname.split("struct.").second;

  } else if (ty->isPointerTy()) {
    ty = cast<PointerType>(ty)->getPointerElementType();
    return handleType(ty);
  } else if (ty->isArrayTy()) {
    ty = cast<ArrayType>(ty)->getElementType();
    return handleType(ty);
  } else if (ty->isIntegerTy()) {
    return StringRef("int");
  }

  return StringRef("");
}
