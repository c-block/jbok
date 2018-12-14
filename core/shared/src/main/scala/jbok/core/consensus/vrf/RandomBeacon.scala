package jbok.core.consensus.vrf

import cats.effect.IO
import jbok.core.ledger.TypedBlock.ReceivedBlock
import jbok.core.models.Address
import Bls._

/**
  * 选择组并出块：根据随机数选择出块的组，和要出的块
  * sig:上一个块的签名,从上一个BlockHeader中取
  * 0.选择组(List[exchangeGroup],sig:随机数) => exchangeGroup
  * 1.判断自己是否属于出块的组(address:自身的地址,exchangeGroup) => Boolean
  * case true=>  2
  * case false=> doNothing
  * 收到很多广播的List[unsignedBlock]
  * 2.选择要出的块(List[unsignedBlock]，sig: 随机数)=> unsignedBlock
  * 3.组签名(exchangeGroup,sharedSeckey:组的密钥份额,unsignedBlock:需要签名的块) => signedSharedBlock:密钥份额签过名的块
  * 4.发送组签名(signedSharedBlock)
  * 5.对每个收到的组签名校验(signedSharedBlock,exchangeGroup,Cache:保存signedSharedBlock的缓存)=>Boolean
  * case true =>保存signedSharedBlock到Cache 并 6
  * case false=>丢弃
  * 6.判断是否达到阈值(t:阈值,exchangeGroup,Cache:缓存)
  * case(acc++ 小于 t)=>继续等待
  * case(acc++ >= t) => 7
  * 7.组内签名校验(List[SignedSharedBlock],exchangeGroup)=> (Boolean ,signedBlock)
  * 8.if true -> 广播(signedBlock) ，else ->丢弃
  */
trait RandomBeacon {
  val secretKey: SecretKey
  val publicKey: PublicKey = secretKey.publicKey


  implicit object ReceivedBlockOrdering extends Ordering[ReceivedBlock[IO]] {
    override def compare(p1: ReceivedBlock[IO], p2: ReceivedBlock[IO]): Int = {
      -p1.block.header.beneficiary.toArray.map("%02X" format _).mkString
        .compareTo(p2.block.header.beneficiary.toArray.map("%02X" format _).mkString)
    }
  }

  implicit object AddressOrdering extends Ordering[Address] {
    override def compare(p1: Address, p2: Address): Int = {
      -p1.bytes.toArray.map("%02X" format _).
        mkString.compareTo(p2.bytes.toArray.map("%02X" format _).mkString)
    }
  }

  /**
    * 判断是否属于出块的组
    */
  def onTurnOrNot(address: Address, exchangeGroup: ExchangeGroup): Boolean =
    exchangeGroup.group.members.find(node => node.pubkey.address == address) match {
      case None => false
      case Some(_) => true
    }

  /**
    * 生成分组
    * 根据随机数的perm
    */
  def makeGroups(config: Config): List[Group] = {
    val nodes = config.nodes.toList.sortBy(_.pubkey.address)
    val groups = for {
      i <- 0 until config.m
      members = config.rand.Deri(i).randPerm(config.n, config.k).map(i => nodes(i)).toList
      group = Group(members, config.k, config.rand)

    } yield group
    groups.toList
  }

  /**
    * 选择出块的组
    */
  def chooseGroup(groups: List[ExchangeGroup], rand: Rand): ExchangeGroup = {
    val index = rand.int.mod(groups.length)
    val groupsSorted = groups.sortBy(_.group.address)
    groupsSorted(index.toInt)
  }

  /**
    * 选择要出的块
    */
  def chooseBlock(blocks: List[ReceivedBlock[IO]], rand: Rand): ReceivedBlock[IO] = {
    val index = rand.int.mod(blocks.length)
    val blocksSorted = blocks.sorted
    blocksSorted(index.toInt)
  }

  /**
    * 为所有组生成 密钥份额
    */
  def sharesGroups(groups: List[Group]): List[Shares] = groups.map(group => group.generateShares)

  /**
    * 分发密钥
    */
  def sendShares(group: Group, shares: Shares): IO[Unit]

  /**
    * 广播区块
    */
  def broadcastBlock(block: ReceivedBlock[IO]): IO[Unit]

  /**
    * 发送由自身签名的
    */
  def sendSignedSharedMessage(message: Message): IO[Unit]

}


//会员加入


//组加入


//0.申请会员(endorsement:其他机构颁发的背书) => transaction:生成特殊交易

//0.选择随机数(number:block高度，BlockHeader:当前块头， genesis :创始块 ,epochNumber:纪元,)=> sig:随机数
// (if number==0 genesis创始块中选择 else blockHeader中选择)



