import re
from typing import Union

from pathlib import Path


def sanitize(path: Union[Path, str]) -> Path:
    if isinstance(path, str):
        path = Path(path)
    paths = [path.name, *[p.name for p in path.parents if p.name]][::-1]
    for i, p in enumerate(paths):
        p = p.replace('...', '').strip()
        p = re.sub(r'[<>:"/|?*\x00-\x1F]', '_', p)
        paths[i] = p

    return Path().joinpath(*paths)


if __name__ == '__main__':
    path = Path() / 'hello rgtgr/sdg'
    print(path)
    path = sanitize(path)
    print(path)
