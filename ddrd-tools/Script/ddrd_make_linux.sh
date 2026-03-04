export PATH=/home/zzzccc/DDRD/compiler/:$PATH
export LD_LIBRARY_PATH=/home/zzzccc/llvm-15/llvm-project/build/lib:$LD_LIBRARY_PATH

make CC="clang-wrapper.sh" defconfig
make CC="clang-wrapper.sh" defconfig kvm_guest.config 


make CC="clang-wrapper.sh" olddefconfig
bear -- make CC="clang-wrapper.sh" HOSTCC="clang-wrapper.sh" -j$(nproc)

