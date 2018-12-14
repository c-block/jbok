package jbok.core.consensus.vrf

import cats.effect.{IO}
import jbok.core.ledger.TypedBlock.ReceivedBlock
import jbok.core.models.{Address, BlockHeader}
import cats.implicits._
import Bls._


/**
  *  1.todo 状态图
  *  2.Node 中的address放到publickey中 , 推后(implicit C:Cache[SecretKey])
  *  3.有些地方发送message就可以了
  *  4.senderAddress发送者的地址需要保存
  * 5.
  */

/**
  * 创世:所有的分组必须先分好，并且分组信息存储在创世块上
  * 0.config(Set(Node:节点):初始成员,sig:固定的随机数，m:多少组，n:组大小,k:阈值)
  * 1.分组(Set[PublicKey:节点]，m:多少组，n:组大小,k:阈值，sig:随机数)=> List[Group]:组
  * 2.为每个组生成组密钥份额(Group:组) =>  Shares:密钥份额(Map[组内其他成员地址,SecKey:密钥份额],List[PubKey]:组公钥份额)
  * List[Group]=> List[Shares]
  * 3.为每个组分发密钥份额(shares:密钥份额,ips:组成员地址)=> Unit
  * 4.验证每个密钥正确性(Group,Seckey,List[PubKey]:组公钥份额,address:自身地址)=>Boolean
  * case true=>5
  * case false=>doNothing
  * 5.收集密钥份额(Group:组，SecKey:密钥,sendAddress,List[PubKey]:组公钥份额)
  * case(group) =>group
  * case(exchangegroup) =>保存exchangeGroup:新分组  并 6
  * List[Group]=>List[exchangeGroup]
  * 6.生成创世块(Set(PublicKey:节点),sig:固定的随机数，m:多少组,n:组大小,k:阈值，List[exchangeGroup])=>Genesis
  *
  */
case class Config(nodes: Set[Node], rand: Rand, m: Int, n: Int, k: Int)

//分享的密钥份额
case class Shares(shareSecKeys: Map[Address, SecretKey], sharePubKeys: List[PublicKey])

case class Genesis(nodes: Set[Node], rand: Signature, m: BigInt, n: BigInt, k: BigInt, groups: List[Group])

// sharedSignature：共享密钥的签名 ，signature: 节点自身密钥的签名
case class Message(sharedSignature: Signature, blockHeader: BlockHeader, from: Address, signature: Signature)

case class Node(pubkey: PublicKey, pop: Signature) {

  /**
    * 验证收到的密钥正确性，BLS
    *
    */
  def verifyShare(publicKeyVec: List[PublicKey], secretShareKey: SecretKey): Boolean = {
    //todo 拆一下
    publicKeyVec.map(a => Bls.getG2Element(a.bytes.toArray)).reverse.takeRight(publicKeyVec.length - 1)
      .foldLeft(Bls.getG2Element(publicKeyVec(publicKeyVec.length - 1).bytes.toArray))((result, publicKey) =>
        result.mulZn(Bls.getZrElement(pubkey.address.bytes.toArray).add(publicKey))).
      toBytes.equals(secretShareKey.publicKey.bytes.toArray)

  }

  /**
    * 生成创世块
    */
  //  def createGenesis(nodes: Set[Node], rand: Signature, m: Int, n: Int, k: Int, groups: List[Group]): Genesis =
  //    Genesis(nodes, rand, m, n, k, groups)
}

sealed trait TypedGroup

// todo sharePublicKeys 是 用于校验 签名份额的
case class Group(members: List[Node], threshold: Int, rand: Rand, receivedShares: Map[Address, SecretKey] = Map.empty, sharePublicKeys: Map[Address, PublicKey] = Map.empty) extends TypedGroup {

  val address: Address = ???
  val priVec: List[SecretKey] = (0 until threshold).map(i => SecretKey(Bls.getZrElement(rand.Deri(i)).toBytes)).toList
  val pubVec: List[PublicKey] = priVec.map(seckey => seckey.publicKey)

  /**
    * 生成密钥份额,根据组的随机数种子
    */
  def generateShares: Shares =
    Shares(shareSecKeys = members.map(node => node.pubkey.address)
      .map(address => (address -> generateShare(address))).toMap, sharePubKeys = pubVec
    )


  /**
    * 根据地址生成密钥份额
    */
  def generateShare(address: Address): SecretKey = {
    val priVecR = priVec.map(seckey => Bls.getZrElement(seckey.bytes.toArray)).reverse
    SecretKey(priVecR.takeRight(priVecR.length - 1).foldLeft(priVecR(0))((result, pri) => {
      lazy val addressE = Bls.getZrElement(address.bytes.toArray)
      result.mul(addressE).add(pri)
    }
    ).toBytes
    )
  }

  /**
    * f(x)= a0 + a1*address + .... + a(k-1)*(address的k-1次方)
    * publicKeys = [a0,a1,a(k-1)]对应的公钥数组
    */
  def aggregatePublicKeys(address: Address, publicKeys: List[PublicKey]): PublicKey = {
    PublicKey(publicKeys.map(a => Bls.getG2Element(a.bytes.toArray)).reverse.takeRight(publicKeys.length - 1)
      .foldLeft(Bls.getG2Element(publicKeys(publicKeys.length - 1).bytes.toArray))((result, publicKey) =>
        result.mulZn(Bls.getZrElement(address.bytes.toArray).add(publicKey))).toBytes)
  }

  /**
    * 收集密钥份额：if sender不属于此组 => 返回this  ; else
    */
  def collectShares(senderAddress: Address, secretKey: SecretKey, publicKeys: List[PublicKey]): TypedGroup = {
    //todo Either
    members.find(node => node.pubkey.address == senderAddress) match {
      case None => this
      case Some(value) => {
        receivedShares.contains(value.pubkey.address) match {
          case true => this
          case false => value.verifyShare(publicKeys, secretKey) match {
            case false => this
            case true => receivedShares.size + 1 >= members.length match {
              case false => copy(receivedShares = receivedShares + (senderAddress -> secretKey))
              case true => generateExchangeGroup
            }
          }
        }
      }
    }
  }

  /**
    * 生成 组的公钥和私钥匙
    */
  def generateExchangeGroup(): ExchangeGroup = {

    ExchangeGroup(this, SecretKey(receivedShares.toList.map(_._2).foldLeft(Bls.getZrElement(0))
    ((result, seckey) =>
      result.add(Bls.getZrElement(seckey.bytes))).toBytes), List.empty)
  }

}

// 分组成功后就有了组公钥，私钥
case class ExchangeGroup(group: Group, sharedCombinedSeckey: SecretKey, messages: List[Message]) extends TypedGroup {

  def sharedPublicCombinedKey: PublicKey = sharedCombinedSeckey.publicKey

  /**
    * 组签名,贡献签名份额， 1.共享密钥签名
    */
  def signShareBlock(block: ReceivedBlock[IO], secretKey: SecretKey): Message = {
    val sharedSig = Bls.sign(block.block.header.mixHash, sharedCombinedSeckey)
    val sig = Bls.sign(block.block.header.mixHash, secretKey)
    Message(sharedSig, block.block.header, secretKey.publicKey.address, sig)
  }

  /**
    * todo  Ref ，抛到上层
    * 收集block签名 ，调用 verifySigShareBlock ，验证通过之后放入到 Cache中
    */
  //    def collectBlockSigs(message: Message): IO[Unit] = {
  //       verifySignedShareBlock(message) match {
  //         case false => IO.pure()
  //         case true if messages.length>=group.threshold=>if(verifySharedSignatures)
  //         case _ =>
  //       }
  //    }

  /**
    * 验证某一份share签名 0.得到节点公钥 1.验证节点sig 2.验证节点sig份额
    */
  def verifySignedShareBlock(message: Message): Boolean = {
    group.members.map(node => node.pubkey).find(pub => pub.address == message.from) match {
      case None => false
      case Some(t) => Bls.verify(message.blockHeader.mixHash, t, message.signature) match {
        case false => false
        case true => Bls.verify(message.blockHeader.mixHash, group.sharePublicKeys(message.from), message.sharedSignature)
      }
    }
  }

  /**
    * 收集到所有签名份额后，验证
    */
  def verifySharedSignatures: Boolean =
    messages.find(message => verifySignedShareBlock(message) == false) match {
      case None => true
      case Some(_) => false
    }
}



