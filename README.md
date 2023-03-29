本项目是在 [n2n官方v2.8.0](https://github.com/ntop/n2n/tree/2.8-stable) 的基础上做了一些微调，以便于大家更愉快的使用v2. 以下仅记录修改/增加的部分：

1. 2022-12-25：v2.8.1 版，增加 auto ip 功能；
2. 2023-01-06：修改主程序的帮助信息以及其监视口的输出格式，便于阅读；
3. 2023-01-07：“多线程”的体验见 2.8.x-pthread 分支(作者 [Oliver0624](https://github.com/Oliver0624));
4. 2023-03-15：v2.8.2 版，速度和稳定性都有一定提升，推荐使用；
5. 2023-03-29：今年大家都忙，可能要停留一段时间再有重要更新了 ... ...

如果你愿意帮助增加新的功能，请加入QQ群(196588661)讨论后再进行。

---

### 编译方法

直接编译（ubuntu）<pre>
法一：（第二条可以不用，但可以在后面跟参数，例如 CFLAGS="-static"，实现静态编译）
./autogen.sh
./configure
make
法二：（编译静态是在 cmake 里加入 -DCMAKE_EXE_LINKER_FLAGS="-static"）
mkdir build && cd build
cmake -G "Unix Makefiles" -DCMAKE_SYSTEM_NAME="Linux" -DCMAKE_BUILD_TYPE="Release" -DCMAKE_VERBOSE_MAKEFILE=ON --build -B ./ -S ../
make</pre>

交叉编译（在 ubuntu 下编译 mipsel 的程序）<pre>
法一：
HOST_TRIPLET=mipsel-openwrt-linux-uclibc
apt-get install binutils-$HOST_TRIPLET gcc-$HOST_TRIPLET # 这一条可以不要？
./autogen.sh
export CC=$HOST_TRIPLET-gcc
export AR=$HOST_TRIPLET-ar
./configure --host $HOST_TRIPLET CFLAGS="-O2"
make
法二：
mkdir build && cd build
cmake -G "Unix Makefiles" -DCMAKE_SYSTEM_NAME="Linux" -DCMAKE_BUILD_TYPE="Release" -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_C_COMPILER=${TOOLCHAIN}-gcc -DCMAKE_CXX_COMPILER=${TOOLCHAIN}-g++ --build -B ./ -S ../
make</pre>
