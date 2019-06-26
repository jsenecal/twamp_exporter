from setuptools import setup

setup(
    name='twamp_exporter',
    version='0.1',
    py_modules=['twamp_exporter'],
    install_requires=[
       'click',
        'click-log',
'schedule',
'prometheus-client'
    ],
    entry_points='''
        [console_scripts]
        twamp_exporter=twamp_exporter:runner
    ''',
)