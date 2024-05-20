import subprocess

def runCommand(cmd, output='Pipe'):
    if output == None:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elif output == 'Pipe':
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    elif output == 'stdout':
        proc = subprocess.Popen(cmd, shell=True)
    else:
        with open(output, 'w') as fd:
            proc = subprocess.Popen(cmd, shell=True, stdout=fd, stderr=fd)

    #proc.wait()
    (out, err) = proc.communicate()
    outStr = ""
    errStr = ""
    if output == 'Pipe':
        outStr = str(out.decode("utf-8"))
        errStr = str(err.decode("utf-8"))
    return (proc.returncode, outStr, errStr)