import pexpect
import sys
def expect_sendline(child,exp,para,timeout = 30):
    child.expect(exp,timeout)
    child.sendline(para)
def main(argv):
    filename = argv[1]
    try:
        child = pexpect.spawn("phoronix-test-suite run apache osbench sqlite-speedtest sockperf compress-7zip ffmpeg openssl redis")
        print("start")
        expect_sendline(child,"Concurrent Requests","3")
        print("Apache")
        expect_sendline(child,"OSBench","5")
        print("OSBench")
        expect_sendline(child,"Sockperf","3")
        print("Sockperf")
        expect_sendline(child,"FFmpeg","1")
        print("FFmpeg")
        expect_sendline(child,"Scenario","1")
        print("FFmpeg_paras")
        expect_sendline(child,"OpenSSL","2")
        print("OpenSSL")
        expect_sendline(child,"Redis","1")
        print("Redis")
        expect_sendline(child,"Parallel","1")
        print("Redis_paras")
        expect_sendline(child, "save these test results", "y")
        print("save results")
        expect_sendline(child, "Enter a name", filename)
        print("enter name")
        expect_sendline(child, "Enter a unique name", "xxxx")
        print("enter unique name")
        expect_sendline(child, "New Description", "xxxx")
        print("enter description")
        child.expect("Sockperf")
        print("successfully run")
        expect_sendline(child, "view the results", "n",10000)
        expect_sendline(child, "upload the results", "n")
        print("finished")
    finally :
        print(child.before.decode())

if __name__ == "__main__":
    main(sys.argv)