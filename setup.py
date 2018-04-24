from setuptools import setup

setup(name='cloudgenix_get_all_interface_info',
      version='1.1.0',
      description='Utility to dump all CloudGenix App Fabric Interface configurations to a CSV.',
      url='https://github.com/ebob9/get-all-interface-info',
      author='Aaron Edwards',
      author_email='cloudgenix_get_all_interface_info@ebob9.com',
      license='MIT',
      install_requires=[
            'cloudgenix >= 4.5.5b2',
            'progressbar2 >= 3.34.3'
      ],
      packages=['cloudgenix_get_all_interface_info'],
      entry_points={
            'console_scripts': [
                  'get-all-interface-info = cloudgenix_get_all_interface_info:go',
                  ]
      },
      classifiers=[
            "Development Status :: 5 - Production/Stable",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3"
      ]
      )
