"""Run the unchanged archive oracle through the native fifteen-case domain."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


def main():
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    checkout=Path.cwd().resolve()
    binding_file=Path(sys.argv[1]).resolve(strict=True)
    binding=json.loads(binding_file.read_bytes())
    spec=importlib.util.spec_from_file_location('distribution_oracle',checkout/'tools/check_distribution.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def guarded(argv,*,cwd,env,check,capture_output,text,timeout):
        if (argv!=[sys.executable,'-c',module._PYTEST_PROBE,str(checkout)]
                or check or not capture_output or not text or timeout!=120):
            raise RuntimeError('archive exact original runner invocation')
        # The host's trace expires at100s, then its owned cleanup runs. TERM at
        #110s reaches the host's cleanup/encryption finally before the120s oracle
        #deadline; a final kill is a failure, never successful cleanup evidence.
        result=subprocess.run(['/usr/bin/timeout','--signal=TERM','--kill-after=5','110',
            sys.executable,'-I','-B',str(Path(binding['support'])/'source_host.py'),
            str(binding_file),'archive15',str(cwd)],cwd=checkout,check=False,timeout=120)
        record=json.loads((binding_file.parent/'archive-private/source-result.json').read_bytes())
        from postbuild_root import CASES
        if result.returncode or record['completed']!=list(CASES) or record['trace_poison'] or record['failure']:
            raise RuntimeError('guarded archive persistence did not pass; private evidence retained')
        output=base64.b64decode(record['output_base64'],validate=True).decode()
        return subprocess.CompletedProcess(argv,0,output,'')
    result=module.check_distribution(checkout,checkout/'dist',run_process=guarded)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    main()
