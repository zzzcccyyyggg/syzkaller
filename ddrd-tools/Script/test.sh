cd /home/test/DDRD/
rm -rf build
mkdir build
cd build
cmake ..
make -j4
mkdir /mnt/btrfs
mount /dev/sdb /mnt/btrfs
./bin/KCCWFExecutor --race-reproduce --b /home/test/corpus_elf


# cd /home/test/DDRD/
# rm -rf build
# mkdir build
# cd build
# cmake ..
# make -j4
# mkdir /mnt/btrfs
# mount /dev/sdb /mnt/btrfs
# ./bin/KCCWFExecutor /home/test/corpus_elf --dry_run

# cd /home/test/DDRD/
# rm -rf build
# mkdir build
# cd build
# cmake ..
# make -j4
# mkdir /mnt/btrfs
# mount /dev/sdb /mnt/btrfs
# ./bin/KCCWFExecutor /home/test/corpus_elf --run_fuzz