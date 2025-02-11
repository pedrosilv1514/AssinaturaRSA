# AssinaturaRSA

1. Verificador de Integridade de Arquivos Assinados
O usuário pode carregar um arquivo de texto e assinar digitalmente usando sua chave privada.
O programa salva a assinatura junto ao arquivo.
Outro usuário pode carregar esse arquivo e a assinatura para verificar sua autenticidade usando a chave pública do remetente.
🔹 Fluxo:
O usuário assina um arquivo TXT, e a assinatura é anexada ao final do arquivo.
Outro usuário pode carregar o arquivo e a assinatura e verificar se o conteúdo foi alterado.


## Dica do usuario privado
cat ~/.rsa_keys/Pedro_private.pem
