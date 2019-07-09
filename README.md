# CTIMiner

This is the CTI dataset generator from public APT reports.
The specified description of this system and the dataset are under publication.

This source code is tested on python 2.7, MISP 2.4.109 operated on Ubuntu 18.04.

## System Architecture
<p align="center">
  <img src="https://user-images.githubusercontent.com/13994685/39529573-faed5d70-4e61-11e8-83b7-5ff3f99eb6a9.jpg" width="700" title="systemarchitecture">
</p>

## Event Data Structure and Example
Following is the event data structure and the comments for each data elements.
<p align="center">
  <img src="https://user-images.githubusercontent.com/13994685/39529755-65aefe84-4e62-11e8-879a-cea3ddb6c6b0.jpg" width="500" title="eventdatastructure">
</p>

Following is the example of event data. The left image is the report event and the right one is corresponding malware event.
Data in the report event dataset is retrieved from security reports by the parser, and that in the malware event is extracted from the analysis results from the malware repository.

![eventdataexample](https://user-images.githubusercontent.com/13994685/39529764-69100168-4e62-11e8-916b-16a8252b5506.jpg)

## Download Dataset (updated: 2019/07/09)
The generated CTI dataset covers the security reports published from 2008 to June 2019. It can be downloaded from the following links:

| Year  | Report event | Malware event |
| ------------- | ------------- | ------------- |
| 2008  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgxXYo31MJo2e5mON?e=XRGU0d) | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgxNzDECD1Wsj5kZA?e=5E0PDz) |
| 2009  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgxYM4rMMUYbUU4F0?e=eZzsB5) | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgxSpJHMj4A8OSC8Q?e=OA4AAS) |
| 2010  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgxd3caC7pW5hdZKr?e=vGIkq6) | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgxiE8rpt2s9yzWMi?e=cfLHMR) |
| 2011  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgxkwDtRAF7jTcSKS?e=H9UEgj) | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgxpXoYS0zr_qa8Gr?e=s2EGrP) |
| 2012  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgxzZ9tmqfupxHHkG?e=ngww9M) | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgxsrM0yZw7a4PyTl?e=bDBRRQ) |
| 2013  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgx2XjfGPwWG0IwfU?e=YFoOx3) | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgx7DUTOZCAFSzE4a?e=hHCOxd) |
| 2014  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgyBPQEmDyXoUIMyc?e=gi6IQo) | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgx8tXmdQ_K87Gd2F?e=FbQAxV) |
| 2015  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgyEBoayYYGE-TYrE?e=laF8Ft) | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgyLyna9hpTq3cI-l?e=Xv14NP) |
| 2016  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgyTkJvV54QeNd8IU?e=FALJjC) | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgyPQZ_yqyjYToDw3?e=ZKTSnb) |
| 2017  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgyYkf-RCedJ6Q9IZ?e=apdgwL) | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgyV-MzSN-JK-SJr9?e=qqXmLo) |
| 2018  | [Download](https://1drv.ms/u/s!Al-x4GEOffcqgyfpiHw8YOzm_skD?e=Zdi2DA) | [Download]() |
| 2019 (~June)  | [Download]() | [Download]() |
