```
https://github.com/lucktu/n2n_ntop/tree/2.7-r525
Clone: 
git clone -b 2.7-r525 https://github.com/lucktu/n2n_ntop.git
```

��� PR ������ n2n �ٷ�Դ�� (v2.7_523.92dfa67����ʵ�Ѿ��ܽӽ��ٷ������� v2.8 �汾��)��Ŀ����Ϊ�˸� n2n_v2 
����һ�� AutoIP �Ĺ��ܣ��ٷ������µ� v2.8 �����Ѿ�ȥ����������ܣ��������ڴ˻����������� edge �� supernode 
�İ�����Ϣ���Ա���ʹ�á�

The pr is from the N2N official source code(v2.7_523.92dfa67, it's actually pretty close to the official final V2.8),
the purpose is to preserve the functionality of an AutoIP for n2n_v2(it's not available in the latest V2.8). 
We add edge & supernode's help, make it easy to use.

��Ȼ��Ҳ����ȥ�������عٷ�Դ��

You can also download the official source code here

https://github.com/ntop/n2n/tree/92dfa67e2263a9dedae91c177f822b86a04de5a4




���������� 2021-9-26

Reorganized on September 26,2021

=======================================================

Ϊ�ٷ�Դ��(v2.7_r523)���ϰ�����Ϣ�ķ���

Modify form v2.7_r523 to v2.7_r525 (add help for v2.7_r523)

```
//  src/edge.c
  printf("-a <mode:address>        | Set interface address. For DHCP use '-r -a dhcp:0.0.0.0'\n");
to
  printf("-a <mode:address>        | Set interface address. For DHCP use '-r -a dhcp:0.0.0.0'\n"
         "                         | default(no -a) is autoip, eg. 172.17.12.x\n");


//  src/sn.c
	printf("-d <net/bit>  | Subnet that provides dhcp service for edge. eg. -d 172.17.12.0/24\n");
to
	printf("-d <net/bit>  | Set an automatically assigned subnet for edge, default -d 172.17.12.0/24\n");
```
