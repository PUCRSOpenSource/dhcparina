# dhcparina

## Objetivo

Implementar um programa que envia mensagens **DHCP** para os clientes
que solicitam endereços **IPv4**, para a execução de um ataque do tipo
_man-in-the-middle_.

## Descrição

Os alunos devem construir, com base na implementação de um _socket_
***RAW***, utilizando de nível de enlace e protocolo **IPv4** para envio
e recepcção de pacotes **DHCP**. **Não serão aceitos trabalhos que
apenas instalam e configuram servidores DHCP. É requerida a
implementação de um programa capaz de reconhecer as principais mensagens
e seja capaz de enviar mensagens para configuração dos clientes.**

O ataque, que simula o servidor **DHCP**, deve identificar os pedidos de
endereço dos _hosts_ clientes e deve enviar as mensagens necessárias
para a configuração do host.

O resultado esperado é a execução de um ataque do tipo
_man-in-the-middle_ através do envio de mensagens **DHCP** forjadas, de
forma a controlar a rota _default_ dos _hosts_ da rede local e a
resolução de endereços **DNS**.

O trabalho requer a instalação e configuração de um servidor **DNS**, ou
a implementação de outro programa para o envio de mensagens **DNS** de
resolução de endereços, para responder às consultas de resolução de
nomes. Neste servidor/programa, devem ser configurados alguns endereços
de sites conhecidos, mas com endereços **IP** de outros sites, de forma
que o intruso possa controlar a página que o usuário está acessando.

A aplicação deve ter um modo de apresentação na tela das solicitações
reconhecidas e respondidas do **DHCP** e do **DNS** (no caso de
implementação de um programa específico). Além disso, o intruso deve
apresentar uma tela que demonstra o controle sobre o roteamento dos
pacotes pelo gateway _default_ intruso.

## Resultados e Entrega

- **Grupos:** máximo 2 alunos.
- **Entrega:** Apresentação em aula + Relatório descrevendo a
  implementação
- **Data Entrega e Apresentação: 03/07/2018**
