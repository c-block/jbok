package jbok.core.consensus.vrf

import jbok.JbokSpec

class RandomBeaconSpec extends JbokSpec {

  // todo testkit自动生成一些重要数据 , 优化code放到最后面

  //1. 验证密钥份额(node:节点, List[PublicKey]:共享的公钥组, secretShareKey: 共享的私钥)
  //2. 验证组签名(groupSharePublicKey:组公钥,List[Signature]:签名组,签名信息:Message)
  //3. 验证消息正确(node:节点,message:消息)
  //4. 验证组的私钥与分享之后的密钥相等(List[SecretKey]:所有人的私钥,List[SecretKey]:所有共享得到的密钥)
  //5. 验证组的公钥匙与分享后的公钥相等(List[PublicKey]:所有的的公钥,List[PublicVec]:所有人的共享密钥组)
  //6. 收集密钥份额 todo
  //7. 收集签名份额 todo

  "verifyShare" should {

    "validate correctly a valid (secretShare, PublicKey list) pair" in {

    }

    "report a invalid secretShare " in {

    }

    "report a invalid publicKey list with insufficient length " in {

    }

    "report a invalid publicKey list with duplicated publicKey " in {

    }

    "report a invalid publicKey list with wrong Keys " in {

    }

    "report a invalid node list with duplicated node " in {

    }

  }


  "verifySignature" should {

    "validate correctly a valid (groupSharePublicKey, Signature list,message) " in {

    }

    "report a invalid groupSharePublicKey " in {

    }

    "report a invalid Signature list with insufficient length " in {

    }

    "report a invalid Signature list with wrong Signatures " in {

    }

    //    "report a invalid message  " in {
    //
    //    }
  }

  "verifyMessage" should {

    "validate correctly a valid message " in {

    }

    "report a invalid message.signature " in {

    }

    "report a invalid message.shareSignature " in {

    }

    //    "report a invalid message.address  " in {
    //
    //    }
    //
    //    "report a invalid message.blockHeader " in {
    //
    //    }
  }

  "verifyGroupSecret" should {

    "validate correctly a valid  " in {

    }

    "report a invalid secretKey list with insufficient length " in {

    }

    "report a invalid secretKey list with wrong secretKey " in {

    }

    "report a invalid share Key list with insufficient length  " in {

    }

    "report a invalid share Key list with wrong share Key " in {

    }
  }


  "verifyGroupPublicKey" should {

    "validate correctly a valid  " in {

    }

    "report a invalid publicKey list with insufficient length " in {

    }

    "report a invalid publicKey list with wrong secretKey " in {

    }

    "report a invalid share Public Key list with insufficient length  " in {

    }

    "report a invalid share Public Key list with wrong share Key " in {

    }
  }


}
