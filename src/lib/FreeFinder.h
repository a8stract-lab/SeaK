#ifndef FREE_FINDER_H
#define FREE_FINDER_H

#include "Common.h"
#include "GlobalCtx.h"

using namespace llvm;

class FreeFinderPass : public IterativeModulePass {

private:
  StringRef targetSt;
  StringRef handleType(Type *ty);

public:
  FreeFinderPass(GlobalContext *Ctx_, StringRef St)
      : IterativeModulePass(Ctx_, "FreeFinder") {
    targetSt = St;
  }
  virtual bool doInitialization(Module *);
  virtual bool doFinalization(Module *);
  virtual bool doModulePass(Module *);

  void dump();
};

#endif
