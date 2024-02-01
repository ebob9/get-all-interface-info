from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup(name='prisma_sdwan_get_all_interface_info',
      version='2.0.1',
      description='Utility to dump all CloudGenix App Fabric Interface configurations to a CSV.',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/ebob9/get-all-interface-info',
      author='Aaron Edwards',
      author_email='prisma_sdwan_get_all_interface_info@ebob9.com',
      license='MIT',
      install_requires=[
            'prisma-sase >= 6.3.1b1',
            'progressbar2 >= 3.34.3'
      ],
      packages=['prisma_sdwan_get_all_interface_info'],
      entry_points={
            'console_scripts': [
                  'get-all-interface-info = prisma_sdwan_get_all_interface_info:go',
                  ]
      },
      classifiers=[
            "Development Status :: 5 - Production/Stable",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 3"
      ]
      )
