# Udacity-FSND-Catalog-Project
This project makes a catalog for items in specific categories. It also implements logins using OAuth 2.0, allowing registered users to add, edit and delete items which they own.

## Requirements
* Python 2
* Vagrant
* VirtualBox

## Installation
1. First to install Vagrant and Virtualbox following these specified [instructions](https://classroom.udacity.com/nanodegrees/nd004/parts/8d3e23e1-9ab6-47eb-b4f3-d5dc7ef27bf0/modules/bc51d967-cb21-46f4-90ea-caf73439dc59/lessons/5475ecd6-cfdb-4418-85a2-f2583074c08d/concepts/14c72fe3-e3fe-4959-9c4b-467cf5b7c3a0). 

1.bAlternatively simply install both of these here [Vagrant](https://www.vagrantup.com/downloads.html)  [VirtualBox](https://www.virtualbox.org/wiki/Downloads) for your appropriate operating system.
2.Next download the files from this (LINK)[https://github.com/udacity/fullstack-nanodegree-vm] and put them in an appropriate directory.
3.Navigate to where you unzipped those files and run `vagrant up` then `vagrant ssh`.
4.Place the files from this directory into the `/vagrant` folder that is shared between your computer and the virtual machine. 
5.Finally to setup and populate the database please run `python database_setup.py` and `python populate.py`

Simply type ` python application.py ` to start up this Flask Server. 
The specified vagrant file should in theory give you all the dependencies needed to run this project.