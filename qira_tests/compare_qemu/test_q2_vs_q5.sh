
set -x

mkdir -p qemu_binaries
mkdir -p parsed_logs
mkdir /tmp/qira_logs/
rm -rf qemu_binaries/* parsed_logs/* /tmp/qira_logs/*



docker build -t qira_q2 -f Dockerfile_q2 .
docker build -t qira_q5 -f Dockerfile_q5 .


docker rm c_qira_q2
docker rm c_qira_q5

docker run --name=c_qira_q2 qira_q2
docker run --name=c_qira_q5 qira_q5

docker cp c_qira_q2:/qemu_build/x86_64-linux-user/qemu-x86_64 qemu_binaries/qemu_v2
docker cp c_qira_q5:/qemu_build/build/qemu-x86_64 qemu_binaries/qemu_v5

docker rm c_qira_q2
docker rm c_qira_q5


export QEMU_KRM_NO_STACK=1
export QEMU_KRM_NO_MMAP=1
export QEMU_KRM_NO_PIE=1
TARGET=../bin/loop_static
./qemu_binaries/qemu_v2 -strace -d in_asm,nochain -singlestep --tracelibraries $TARGET
./qemu_binaries/qemu_v5 -strace -d in_asm,nochain -singlestep --tracelibraries $TARGET

python ../../middleware/qira_log.py /tmp/qira_logs/0 > parsed_logs/0.txt
python ../../middleware/qira_log.py /tmp/qira_logs/1 > parsed_logs/1.txt

diff parsed_logs/0.txt parsed_logs/1.txt > parsed_logs/log.diff

qira -s --no-clear $TARGET

