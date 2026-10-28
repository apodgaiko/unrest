"""Test data for the public launch-proposal wire shape; grants no authority."""


def operands(value):
    return {'case': value.case, 'executable': value.argv[0], 'argv': list(value.argv),
            'cwd': value.cwd, 'environment': dict(value.environment), 'stdin': None}
