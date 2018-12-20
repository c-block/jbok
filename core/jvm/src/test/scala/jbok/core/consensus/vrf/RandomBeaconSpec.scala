package jbok.core.consensus.vrf

import jbok.JbokSpec
import jbok.common.testkit._
import jbok.core.consensus.vrf.Bls.{PublicKey, SecretKey, Signature}
import testkit._
import jbok.core.models.{Address, BlockHeader}
import jbok.core.testkit._
import scodec.bits.ByteVector
import scodec.bits._


case class TestShare(pubVec: List[PublicKey], secretKeyShare: SecretKey)


class RandomBeaconSpec extends JbokSpec {


  // todo testkit自动生成一些重要数据 , 优化code放到最后面
  // todo 判空问题还是有点模糊,组的模仿是放在mine和run中吗

  //1. 验证密钥份额(node:节点, List[PublicKey]:共享的公钥组, secretShareKey: 共享的私钥)
  //2. 验证消息正确(node:节点,message:消息)
  //3. 验证组签名(groupSharePublicKey:组公钥,List[Signature]:签名组,签名信息:blockHash)
  //4. 验证组的公钥匙与分享后的公钥相等(List[PublicKey]:所有的的公钥,List[PublicVec]:所有人的共享密钥组)
  //5. 收集密钥份额(Address: 发送者地址, SecretKey: 密钥份额, List[PublicKey]:公钥组 )
  //6. 收集签名份额(Message: 收集到的信息 )
  //  整体流程测试
  //7. 生成组 todo
  //8. 接收区块 todo

  def genereateShare(node: Node, rand: Rand, threshold: Int): TestShare = {
    val priVec: List[SecretKey] = (0 until threshold).map(i => SecretKey((rand.Deri(i).bytes))).toList
    val pubVec: List[PublicKey] = priVec.map(seckey => seckey.publicKey)
    val priVecR = priVec.map(seckey => Bls.getZrElement(seckey.bytes)).reverse
    val addressE = Bls.getZrElement(node.pubkey.address.bytes)
    TestShare(pubVec, SecretKey(priVecR.takeRight(priVecR.length - 1).foldLeft(priVecR(0))((result, pri) => {
      result.mul(addressE).add(pri)
    }
    ).toBytes
    ))
  }

  //生成 地址与私钥匙份额的 Map
  def generateShares(rands: List[Rand], nodes: List[Node]): Map[Address, SecretKey] = {
    val shares = for {
      rand <- rands
      node <- nodes
    } yield genereateShare(node, rand, 2)

    val addresses = rands.map(rand => SecretKey((rand.Deri(0).bytes)).publicKey.address)
    val aggShares = shares.map(_.secretKeyShare).zipWithIndex.groupBy(s => (s._2 % 3)).map(_._2).map(arr => (addresses(arr(0)._2 % 3) -> arr.map(_._1))).toList
    val k = aggShares.map(l => (l._1 -> addSecretKey(l._2)))
    val result = addresses.map(addr => (addr -> k.find(pair => pair._1 == addr).get._2))
    result.toMap
  }

  def addPublicKey(publicKeys: List[PublicKey]): PublicKey =
    PublicKey(publicKeys.map(publicKey => publicKey.element).foldLeft(Bls.getG2ElementZero)((result, ele) => result.add(ele)).toBytes)

  def addSecretKey(secretKeys: List[SecretKey]): SecretKey =
    SecretKey(secretKeys.foldLeft(Bls.getZrElementZero)((result, sec) => (result.add(sec.element))).toBytes)


  def generateNode(secretKey: SecretKey): Node = {
    val pub = secretKey.publicKey
    Node(pub, Bls.sign(pub.bytes, secretKey))
  }


  val secrets = (0 until 8).map(_ => random[SecretKey])
  val nodes = secrets.map(generateNode)
  val config: Config = Config(nodes.toSet, Rand("jbok".getBytes))
  val randomBeacons: List[RandomBeacon] = secrets.map(RandomBeacon.apply).toList
  val groups: List[Group] = randomBeacons.last.makeGroups(config)
  val currentRandomBeacon = randomBeacons(0)
  val currentNode = nodes(0)
  val currentGroup = groups(0)

  "Bls" should {
    "validate correctly a valid " in {
      val secretKey = random[SecretKey]
      val data = ByteVector("dfinity".getBytes)
      val sig = Bls.sign(data, secretKey)
      val valid = Bls.verify(data, secretKey.publicKey, sig)
      valid shouldBe true
    }

    "validate  a invalid publicKey " in {
      val secretKey = random[SecretKey]
      val data = ByteVector("dfinity".getBytes)
      val sig = Bls.sign(data, secretKey)
      val valid = Bls.verify(data, random[PublicKey], sig)
      valid shouldBe false
    }
  }

  "verifyShare" should {

    "validate correctly a valid (secretShare, PublicKey list) pair" in {
      val rand = random[Rand]
      val node = random[Node]
      val testShare = genereateShare(node, rand, 2)
      node.verifyShare(testShare.pubVec, testShare.secretKeyShare) shouldBe true
    }

    "report a invalid secretShare " in {
      val rand = random[Rand]
      val node = random[Node]
      val testShare = genereateShare(node, rand, 2).copy(secretKeyShare = random[SecretKey])
      node.verifyShare(testShare.pubVec, testShare.secretKeyShare) shouldBe false
    }

    "report a invalid publicKey list with insufficient length " in {
      val rand = random[Rand]
      val node = random[Node]
      val testShare = genereateShare(node, rand, 5)
      val testShare1 = testShare.copy(pubVec = testShare.pubVec.takeRight(4))
      node.verifyShare(testShare1.pubVec, testShare1.secretKeyShare) shouldBe false
    }

  }

  "verifyMessage" should {

    "validate correctly a valid message " in {
      val message = random[Message]
      val randomBeacon = random[RandomBeacon]
      val node = Node(randomBeacon.publicKey, randomBeacon.sign(randomBeacon.publicKey.bytes))
      val shareKey = random[SecretKey]
      val shareSig = Bls.sign(message.blockHeader.mixHash, shareKey)
      val sig = randomBeacon.sign(message.blockHeader.mixHash)
      val messageV = message.copy(sharedSignature = shareSig, from = randomBeacon.publicKey.address, signature = sig)
      val publicShare = shareKey.publicKey
      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(
        group = exchangeGroup.group.copy(members = node :: exchangeGroup.group.members,
          sharePublicKeys = exchangeGroup.group.sharePublicKeys + (randomBeacon.publicKey.address -> publicShare)))

      exchangeGroupV.verifySignedShareMessage(messageV) shouldBe true
    }


    "report a invalid message.signature " in {
      val message = random[Message]
      val randomBeacon = random[RandomBeacon]
      val node = Node(randomBeacon.publicKey, randomBeacon.sign(randomBeacon.publicKey.bytes))
      val shareKey = random[SecretKey]
      val shareSig = Bls.sign(message.blockHeader.mixHash, shareKey)
      val sig = random[Signature]
      val messageV = message.copy(sharedSignature = shareSig, from = randomBeacon.publicKey.address, signature = sig)
      val publicShare = shareKey.publicKey
      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(
        group = exchangeGroup.group.copy(members = node :: exchangeGroup.group.members,
          sharePublicKeys = exchangeGroup.group.sharePublicKeys + (randomBeacon.publicKey.address -> publicShare)))

      exchangeGroupV.verifySignedShareMessage(messageV) shouldBe false
    }

    "report a invalid message.shareSignature " in {
      val message = random[Message]
      val randomBeacon = random[RandomBeacon]
      val node = Node(randomBeacon.publicKey, randomBeacon.sign(randomBeacon.publicKey.bytes))
      val shareKey = random[SecretKey]
      val shareSig = random[Signature]
      val sig = randomBeacon.sign(message.blockHeader.mixHash)
      val messageV = message.copy(sharedSignature = shareSig, from = randomBeacon.publicKey.address, signature = sig)
      val publicShare = shareKey.publicKey
      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(
        group = exchangeGroup.group.copy(members = node :: exchangeGroup.group.members,
          sharePublicKeys = exchangeGroup.group.sharePublicKeys + (randomBeacon.publicKey.address -> publicShare)))

      exchangeGroupV.verifySignedShareMessage(messageV) shouldBe false
    }

    //    "report a invalid message.address  " in {
    //
    //    } remove something can't be distinguished with invalid signature

  }

  "verifySharedSignature" should {

    //1.构造三个message blockheader固定，from,sharedSignature  2.nodes list
    "validate correctly a valid (groupSharePublicKey, Signature list,blockHash) " in {

      val node1: Node = Node(PublicKey(bytes = hex"009df9a83ad9deb35c97f10ae15f455fc37ea00e1ac941afb31587f141452510abd0d74a5b5c442c4ba97d768b703e00cc1cf1e7b17b77d3a3ea29163be4d4c6c9fffbe473b4e0483215454811a2f897513af70ea5eb87c9e65286799ccf4e01e7ec508967a996cf101a659ff9329384ac09d3362c1da73f0253c00deac8beb313acf8753fbfb851c9512f7998de3bd2056340e98a5b5e99"),
        Signature(bytes = hex"044fc52f5504be023c8edcfaaa28d79b8ede3950f9deaf2f47a9b58d147b4bafe2fca7c52f31b0082df4a2fabe7d3e3736e5ae1a99ece704ccbb20a55ef63289b14a9cd00be044be8f7f2485059ceb9e7e060bfb72d2a2336807456ae5db125ed1d7a1f6a956c01ec15b364a584340d13141fb678b46fc57eaca7bb2a6ecdabd51653b6276b5b5fc8c515694006ba2aaf7a47c9a3db5a299"))
      val node2: Node = Node(PublicKey(hex"0b8264cd7729b1176032e59a100cf665040a52efaaca004e56544ab7fcdbc4866409f2c3f45dfee38c76a8cb2979b0eb94c9b1b40f4ae5175b48804fa1f20884d0d4cb6320439fab2e0bb9b704babaedf507d20b3d825253244664e46ee315e22fd557ff01a7c5ed7c526183d440bd569c17901ef474f74b7a303284317060e5371f9098521cef77aa256fdbb0695cd8d7e4f231356d3b89"),
        Signature(hex"09a49e0f1485575459dbd7e4d81f364f54c97e80d7b5ad8ab973457ce2715ef67395dfe0674385b13ff029950dce0167e27de4d7ee1af21838408a3b379436ab8ad609132c8644eed6d3dfd9066b77f1a5c0bf1f7131b5a0e066396786493e6432df94339bee3d6db233abdb576a16bb38c6c15c14c9226b6d2617bc985a0ca6c45c1ef401b1dcf08f9527ed0cc2e3905292c1923baa5aac"))
      val node3: Node = Node(PublicKey(hex"006e652c9d42bce989e181037650df9a1f42e81fbfc06defe36dfcf0c1fa9afa7b67cdbab4f52eaf2b13067c1dea97a9b75ee601630ebea9ff77141583204addf179f274a642f4c87f09793b0694a2b611cca1ac933049bfa77fcdfd45a2bfd6dd363adfc82d3d9d74e79ad840b0aa98882045ebc6da9bb03bd7c3c966c14161f8b62678331fabd3d66d2333092a65aa3e73f85dd76f5d5a"),
        Signature(hex"06e2d5ec549dfd84c88b69dbceeac8edbd83fc5e708e2cf9ecea256a03a1ee2f001dce33043c42ad9d8c35fc77b598f86998bd3b96c3df7f8abc8f155974189d3fae54959a996bc0c6d14d63171adbbfeaf9f55f788f20746640be50e4d5f599b27422fc0d8c07ca63b0636c9388c7159106ab51e8ac36eb4057f8be4c9bdd8a3f6f9ea293bb97a6227ed8e192aa1c991223655fbb1628eb")
      )
      val members = List(node1, node2, node3)
      val blockHeader = random[BlockHeader].copy(mixHash = ByteVector("dfinity".getBytes()))

      val message1 = random[Message].copy(blockHeader = blockHeader, sharedSignature = Signature(hex"0520d2a21b0aa75cb5439e34aceb58113a430dc0d762815013246cbb449562f11b81e45d149d5402c3ca6048fcb1760e6f855371e3c87b134d1ee2e3e24317d7c416d5692051e55755dd539c17158684b4f4df9dd6965d8693b5f6daf3c38d9a0ee421a00815c2e5894f20e24906ba402bdd4398db8d8086580942c6ae072547ff6dff63447189519ec8bd8e8804bdeffdcac80684cf4c84"), from = Address(hex"b10af4dfd065f2b3074aec74ab523b7783bcbb77"))
      val message2 = random[Message].copy(blockHeader = blockHeader, sharedSignature = Signature(hex"072b1435d1bf7958eb5be57069bb7695a99bf9c041bde64ec0d4c7aac0a0f3c3022caa907723e88f4b934e638a32c4a466d9435f4a2ebc0d5a8a98efef0a1fc44066b2d346eb72bac0d090310f901810223e05c02cd6620ae008701148295eb0a978f2749ebaddb66d5203aa371a0639ed4cdc58130fa85443de570d050e497851e7d71a96e9eefb39cc53d8a0534e86792eeb4239d65f88"), from = Address(hex"d6fd3f5b5954d0f6cb6f4458f54b1ef723e6f4d2"))
      val messages = List(message1, message2)
      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(group = exchangeGroup.group.copy(members = members), messages = messages)

      exchangeGroupV.verifySharedSignatures shouldBe true
    }

    "report a invalid groupSharePublicKey " in {

      val node1: Node = Node(random[PublicKey],
        Signature(bytes = hex"044fc52f5504be023c8edcfaaa28d79b8ede3950f9deaf2f47a9b58d147b4bafe2fca7c52f31b0082df4a2fabe7d3e3736e5ae1a99ece704ccbb20a55ef63289b14a9cd00be044be8f7f2485059ceb9e7e060bfb72d2a2336807456ae5db125ed1d7a1f6a956c01ec15b364a584340d13141fb678b46fc57eaca7bb2a6ecdabd51653b6276b5b5fc8c515694006ba2aaf7a47c9a3db5a299"))
      val node2: Node = Node(PublicKey(hex"0b8264cd7729b1176032e59a100cf665040a52efaaca004e56544ab7fcdbc4866409f2c3f45dfee38c76a8cb2979b0eb94c9b1b40f4ae5175b48804fa1f20884d0d4cb6320439fab2e0bb9b704babaedf507d20b3d825253244664e46ee315e22fd557ff01a7c5ed7c526183d440bd569c17901ef474f74b7a303284317060e5371f9098521cef77aa256fdbb0695cd8d7e4f231356d3b89"),
        Signature(hex"09a49e0f1485575459dbd7e4d81f364f54c97e80d7b5ad8ab973457ce2715ef67395dfe0674385b13ff029950dce0167e27de4d7ee1af21838408a3b379436ab8ad609132c8644eed6d3dfd9066b77f1a5c0bf1f7131b5a0e066396786493e6432df94339bee3d6db233abdb576a16bb38c6c15c14c9226b6d2617bc985a0ca6c45c1ef401b1dcf08f9527ed0cc2e3905292c1923baa5aac"))
      val node3: Node = Node(PublicKey(hex"006e652c9d42bce989e181037650df9a1f42e81fbfc06defe36dfcf0c1fa9afa7b67cdbab4f52eaf2b13067c1dea97a9b75ee601630ebea9ff77141583204addf179f274a642f4c87f09793b0694a2b611cca1ac933049bfa77fcdfd45a2bfd6dd363adfc82d3d9d74e79ad840b0aa98882045ebc6da9bb03bd7c3c966c14161f8b62678331fabd3d66d2333092a65aa3e73f85dd76f5d5a"),
        Signature(hex"06e2d5ec549dfd84c88b69dbceeac8edbd83fc5e708e2cf9ecea256a03a1ee2f001dce33043c42ad9d8c35fc77b598f86998bd3b96c3df7f8abc8f155974189d3fae54959a996bc0c6d14d63171adbbfeaf9f55f788f20746640be50e4d5f599b27422fc0d8c07ca63b0636c9388c7159106ab51e8ac36eb4057f8be4c9bdd8a3f6f9ea293bb97a6227ed8e192aa1c991223655fbb1628eb")
      )
      val members = List(node1, node2, node3)
      val blockHeader = random[BlockHeader].copy(mixHash = ByteVector("dfinity".getBytes()))

      val message1 = random[Message].copy(blockHeader = blockHeader, sharedSignature = Signature(hex"0520d2a21b0aa75cb5439e34aceb58113a430dc0d762815013246cbb449562f11b81e45d149d5402c3ca6048fcb1760e6f855371e3c87b134d1ee2e3e24317d7c416d5692051e55755dd539c17158684b4f4df9dd6965d8693b5f6daf3c38d9a0ee421a00815c2e5894f20e24906ba402bdd4398db8d8086580942c6ae072547ff6dff63447189519ec8bd8e8804bdeffdcac80684cf4c84"), from = Address(hex"b10af4dfd065f2b3074aec74ab523b7783bcbb77"))
      val message2 = random[Message].copy(blockHeader = blockHeader, sharedSignature = Signature(hex"072b1435d1bf7958eb5be57069bb7695a99bf9c041bde64ec0d4c7aac0a0f3c3022caa907723e88f4b934e638a32c4a466d9435f4a2ebc0d5a8a98efef0a1fc44066b2d346eb72bac0d090310f901810223e05c02cd6620ae008701148295eb0a978f2749ebaddb66d5203aa371a0639ed4cdc58130fa85443de570d050e497851e7d71a96e9eefb39cc53d8a0534e86792eeb4239d65f88"), from = Address(hex"d6fd3f5b5954d0f6cb6f4458f54b1ef723e6f4d2"))
      val messages = List(message1, message2)
      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(group = exchangeGroup.group.copy(members = members), messages = messages)

      exchangeGroupV.verifySharedSignatures shouldBe false

    }

    "report a invalid Signature list with insufficient length " in {

      val node1: Node = Node(PublicKey(bytes = hex"009df9a83ad9deb35c97f10ae15f455fc37ea00e1ac941afb31587f141452510abd0d74a5b5c442c4ba97d768b703e00cc1cf1e7b17b77d3a3ea29163be4d4c6c9fffbe473b4e0483215454811a2f897513af70ea5eb87c9e65286799ccf4e01e7ec508967a996cf101a659ff9329384ac09d3362c1da73f0253c00deac8beb313acf8753fbfb851c9512f7998de3bd2056340e98a5b5e99"),
        Signature(bytes = hex"044fc52f5504be023c8edcfaaa28d79b8ede3950f9deaf2f47a9b58d147b4bafe2fca7c52f31b0082df4a2fabe7d3e3736e5ae1a99ece704ccbb20a55ef63289b14a9cd00be044be8f7f2485059ceb9e7e060bfb72d2a2336807456ae5db125ed1d7a1f6a956c01ec15b364a584340d13141fb678b46fc57eaca7bb2a6ecdabd51653b6276b5b5fc8c515694006ba2aaf7a47c9a3db5a299"))
      val node2: Node = Node(PublicKey(hex"0b8264cd7729b1176032e59a100cf665040a52efaaca004e56544ab7fcdbc4866409f2c3f45dfee38c76a8cb2979b0eb94c9b1b40f4ae5175b48804fa1f20884d0d4cb6320439fab2e0bb9b704babaedf507d20b3d825253244664e46ee315e22fd557ff01a7c5ed7c526183d440bd569c17901ef474f74b7a303284317060e5371f9098521cef77aa256fdbb0695cd8d7e4f231356d3b89"),
        Signature(hex"09a49e0f1485575459dbd7e4d81f364f54c97e80d7b5ad8ab973457ce2715ef67395dfe0674385b13ff029950dce0167e27de4d7ee1af21838408a3b379436ab8ad609132c8644eed6d3dfd9066b77f1a5c0bf1f7131b5a0e066396786493e6432df94339bee3d6db233abdb576a16bb38c6c15c14c9226b6d2617bc985a0ca6c45c1ef401b1dcf08f9527ed0cc2e3905292c1923baa5aac"))
      val node3: Node = Node(PublicKey(hex"006e652c9d42bce989e181037650df9a1f42e81fbfc06defe36dfcf0c1fa9afa7b67cdbab4f52eaf2b13067c1dea97a9b75ee601630ebea9ff77141583204addf179f274a642f4c87f09793b0694a2b611cca1ac933049bfa77fcdfd45a2bfd6dd363adfc82d3d9d74e79ad840b0aa98882045ebc6da9bb03bd7c3c966c14161f8b62678331fabd3d66d2333092a65aa3e73f85dd76f5d5a"),
        Signature(hex"06e2d5ec549dfd84c88b69dbceeac8edbd83fc5e708e2cf9ecea256a03a1ee2f001dce33043c42ad9d8c35fc77b598f86998bd3b96c3df7f8abc8f155974189d3fae54959a996bc0c6d14d63171adbbfeaf9f55f788f20746640be50e4d5f599b27422fc0d8c07ca63b0636c9388c7159106ab51e8ac36eb4057f8be4c9bdd8a3f6f9ea293bb97a6227ed8e192aa1c991223655fbb1628eb")
      )
      val members = List(node1, node2, node3)
      val blockHeader = random[BlockHeader].copy(mixHash = ByteVector("dfinity".getBytes()))

      val message1 = random[Message].copy(blockHeader = blockHeader, sharedSignature = Signature(hex"0520d2a21b0aa75cb5439e34aceb58113a430dc0d762815013246cbb449562f11b81e45d149d5402c3ca6048fcb1760e6f855371e3c87b134d1ee2e3e24317d7c416d5692051e55755dd539c17158684b4f4df9dd6965d8693b5f6daf3c38d9a0ee421a00815c2e5894f20e24906ba402bdd4398db8d8086580942c6ae072547ff6dff63447189519ec8bd8e8804bdeffdcac80684cf4c84"), from = Address(hex"b10af4dfd065f2b3074aec74ab523b7783bcbb77"))
      val message2 = random[Message].copy(blockHeader = blockHeader, sharedSignature = Signature(hex"072b1435d1bf7958eb5be57069bb7695a99bf9c041bde64ec0d4c7aac0a0f3c3022caa907723e88f4b934e638a32c4a466d9435f4a2ebc0d5a8a98efef0a1fc44066b2d346eb72bac0d090310f901810223e05c02cd6620ae008701148295eb0a978f2749ebaddb66d5203aa371a0639ed4cdc58130fa85443de570d050e497851e7d71a96e9eefb39cc53d8a0534e86792eeb4239d65f88"), from = Address(hex"d6fd3f5b5954d0f6cb6f4458f54b1ef723e6f4d2"))
      val messages = List(message1)
      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(group = exchangeGroup.group.copy(members = members), messages = messages)

      exchangeGroupV.verifySharedSignatures shouldBe false
    }

    "report a invalid Signature list with wrong Signatures " in {

      val node1: Node = Node(PublicKey(bytes = hex"009df9a83ad9deb35c97f10ae15f455fc37ea00e1ac941afb31587f141452510abd0d74a5b5c442c4ba97d768b703e00cc1cf1e7b17b77d3a3ea29163be4d4c6c9fffbe473b4e0483215454811a2f897513af70ea5eb87c9e65286799ccf4e01e7ec508967a996cf101a659ff9329384ac09d3362c1da73f0253c00deac8beb313acf8753fbfb851c9512f7998de3bd2056340e98a5b5e99"),
        Signature(bytes = hex"044fc52f5504be023c8edcfaaa28d79b8ede3950f9deaf2f47a9b58d147b4bafe2fca7c52f31b0082df4a2fabe7d3e3736e5ae1a99ece704ccbb20a55ef63289b14a9cd00be044be8f7f2485059ceb9e7e060bfb72d2a2336807456ae5db125ed1d7a1f6a956c01ec15b364a584340d13141fb678b46fc57eaca7bb2a6ecdabd51653b6276b5b5fc8c515694006ba2aaf7a47c9a3db5a299"))
      val node2: Node = Node(PublicKey(hex"0b8264cd7729b1176032e59a100cf665040a52efaaca004e56544ab7fcdbc4866409f2c3f45dfee38c76a8cb2979b0eb94c9b1b40f4ae5175b48804fa1f20884d0d4cb6320439fab2e0bb9b704babaedf507d20b3d825253244664e46ee315e22fd557ff01a7c5ed7c526183d440bd569c17901ef474f74b7a303284317060e5371f9098521cef77aa256fdbb0695cd8d7e4f231356d3b89"),
        Signature(hex"09a49e0f1485575459dbd7e4d81f364f54c97e80d7b5ad8ab973457ce2715ef67395dfe0674385b13ff029950dce0167e27de4d7ee1af21838408a3b379436ab8ad609132c8644eed6d3dfd9066b77f1a5c0bf1f7131b5a0e066396786493e6432df94339bee3d6db233abdb576a16bb38c6c15c14c9226b6d2617bc985a0ca6c45c1ef401b1dcf08f9527ed0cc2e3905292c1923baa5aac"))
      val node3: Node = Node(PublicKey(hex"006e652c9d42bce989e181037650df9a1f42e81fbfc06defe36dfcf0c1fa9afa7b67cdbab4f52eaf2b13067c1dea97a9b75ee601630ebea9ff77141583204addf179f274a642f4c87f09793b0694a2b611cca1ac933049bfa77fcdfd45a2bfd6dd363adfc82d3d9d74e79ad840b0aa98882045ebc6da9bb03bd7c3c966c14161f8b62678331fabd3d66d2333092a65aa3e73f85dd76f5d5a"),
        Signature(hex"06e2d5ec549dfd84c88b69dbceeac8edbd83fc5e708e2cf9ecea256a03a1ee2f001dce33043c42ad9d8c35fc77b598f86998bd3b96c3df7f8abc8f155974189d3fae54959a996bc0c6d14d63171adbbfeaf9f55f788f20746640be50e4d5f599b27422fc0d8c07ca63b0636c9388c7159106ab51e8ac36eb4057f8be4c9bdd8a3f6f9ea293bb97a6227ed8e192aa1c991223655fbb1628eb")
      )
      val members = List(node1, node2, node3)
      val blockHeader = random[BlockHeader].copy(mixHash = ByteVector("dfinity".getBytes()))

      val message1 = random[Message].copy(blockHeader = blockHeader, sharedSignature = random[Signature], from = Address(hex"b10af4dfd065f2b3074aec74ab523b7783bcbb77"))
      val message2 = random[Message].copy(blockHeader = blockHeader, sharedSignature = Signature(hex"072b1435d1bf7958eb5be57069bb7695a99bf9c041bde64ec0d4c7aac0a0f3c3022caa907723e88f4b934e638a32c4a466d9435f4a2ebc0d5a8a98efef0a1fc44066b2d346eb72bac0d090310f901810223e05c02cd6620ae008701148295eb0a978f2749ebaddb66d5203aa371a0639ed4cdc58130fa85443de570d050e497851e7d71a96e9eefb39cc53d8a0534e86792eeb4239d65f88"), from = Address(hex"d6fd3f5b5954d0f6cb6f4458f54b1ef723e6f4d2"))
      val messages = List(message1, message2)
      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(group = exchangeGroup.group.copy(members = members), messages = messages)

      exchangeGroupV.verifySharedSignatures shouldBe false
    }

  }

  "verifyGroupPublicKey" should {
    //1.构造nodes list 2.构造sharedpublicKey
    "validate correctly a valid  " in {
      val node1: Node = Node(PublicKey(bytes = hex"009df9a83ad9deb35c97f10ae15f455fc37ea00e1ac941afb31587f141452510abd0d74a5b5c442c4ba97d768b703e00cc1cf1e7b17b77d3a3ea29163be4d4c6c9fffbe473b4e0483215454811a2f897513af70ea5eb87c9e65286799ccf4e01e7ec508967a996cf101a659ff9329384ac09d3362c1da73f0253c00deac8beb313acf8753fbfb851c9512f7998de3bd2056340e98a5b5e99"),
        Signature(bytes = hex"044fc52f5504be023c8edcfaaa28d79b8ede3950f9deaf2f47a9b58d147b4bafe2fca7c52f31b0082df4a2fabe7d3e3736e5ae1a99ece704ccbb20a55ef63289b14a9cd00be044be8f7f2485059ceb9e7e060bfb72d2a2336807456ae5db125ed1d7a1f6a956c01ec15b364a584340d13141fb678b46fc57eaca7bb2a6ecdabd51653b6276b5b5fc8c515694006ba2aaf7a47c9a3db5a299"))
      val node2: Node = Node(PublicKey(hex"0b8264cd7729b1176032e59a100cf665040a52efaaca004e56544ab7fcdbc4866409f2c3f45dfee38c76a8cb2979b0eb94c9b1b40f4ae5175b48804fa1f20884d0d4cb6320439fab2e0bb9b704babaedf507d20b3d825253244664e46ee315e22fd557ff01a7c5ed7c526183d440bd569c17901ef474f74b7a303284317060e5371f9098521cef77aa256fdbb0695cd8d7e4f231356d3b89"),
        Signature(hex"09a49e0f1485575459dbd7e4d81f364f54c97e80d7b5ad8ab973457ce2715ef67395dfe0674385b13ff029950dce0167e27de4d7ee1af21838408a3b379436ab8ad609132c8644eed6d3dfd9066b77f1a5c0bf1f7131b5a0e066396786493e6432df94339bee3d6db233abdb576a16bb38c6c15c14c9226b6d2617bc985a0ca6c45c1ef401b1dcf08f9527ed0cc2e3905292c1923baa5aac"))
      val node3: Node = Node(PublicKey(hex"006e652c9d42bce989e181037650df9a1f42e81fbfc06defe36dfcf0c1fa9afa7b67cdbab4f52eaf2b13067c1dea97a9b75ee601630ebea9ff77141583204addf179f274a642f4c87f09793b0694a2b611cca1ac933049bfa77fcdfd45a2bfd6dd363adfc82d3d9d74e79ad840b0aa98882045ebc6da9bb03bd7c3c966c14161f8b62678331fabd3d66d2333092a65aa3e73f85dd76f5d5a"),
        Signature(hex"06e2d5ec549dfd84c88b69dbceeac8edbd83fc5e708e2cf9ecea256a03a1ee2f001dce33043c42ad9d8c35fc77b598f86998bd3b96c3df7f8abc8f155974189d3fae54959a996bc0c6d14d63171adbbfeaf9f55f788f20746640be50e4d5f599b27422fc0d8c07ca63b0636c9388c7159106ab51e8ac36eb4057f8be4c9bdd8a3f6f9ea293bb97a6227ed8e192aa1c991223655fbb1628eb")
      )
      val members = List(node1, node2, node3)
      val addrPubPair1=Address(bytes=hex"b10af4dfd065f2b3074aec74ab523b7783bcbb77")->
        PublicKey(bytes=hex"118f521c5f4ff276bdd0185c3d7d8cd75ddaa9a27cef999cd7a98d2136e53d9ce19f07727f80f94d4884fe5a69fbb189f4776bafd5ed1fd6ddf179622a9c07e21362584e0a2b9ad9754faf361627f163d70ac23b0843adb18d2d4b23a0f2a13f7bd193ae7aa98d1d8fa2a0dbff0be1e038c88141facdf76d4f53bf18aaec49db33d22f21dda883b856bde6b7e34aa14af811b684a4762aca")
      val addrSigPair2=Address(bytes=hex"d6fd3f5b5954d0f6cb6f4458f54b1ef723e6f4d2")->
        PublicKey(bytes=hex"0a237dc317e38f4e7e8413297fa18f1d320132a7f917a3dec419b3cb9026626073a7a34586dbe5fe50451684c3f3807c957fbad48fec243fec7a64e43257240b305833a1af133e3aad4874710fed14ac19bbe28f2c115cfe3d7d8fbf63e85047dcd5154c5632354d0deaf22dc5bd04aa08cd102529cd51a07394fe09640a31a260ce30b5df9c325d40a5b2d7f9a8dc117830650e8ef4d160")
      val map=Map.empty+addrPubPair1+addrSigPair2

      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(group = exchangeGroup.group.copy(members = members,sharePublicKeys =map ))

      exchangeGroupV.verifyGroupFormed shouldBe true

    }

    "report a invalid share Public Key list with insufficient length  " in {
      val node1: Node = Node(PublicKey(bytes = hex"009df9a83ad9deb35c97f10ae15f455fc37ea00e1ac941afb31587f141452510abd0d74a5b5c442c4ba97d768b703e00cc1cf1e7b17b77d3a3ea29163be4d4c6c9fffbe473b4e0483215454811a2f897513af70ea5eb87c9e65286799ccf4e01e7ec508967a996cf101a659ff9329384ac09d3362c1da73f0253c00deac8beb313acf8753fbfb851c9512f7998de3bd2056340e98a5b5e99"),
        Signature(bytes = hex"044fc52f5504be023c8edcfaaa28d79b8ede3950f9deaf2f47a9b58d147b4bafe2fca7c52f31b0082df4a2fabe7d3e3736e5ae1a99ece704ccbb20a55ef63289b14a9cd00be044be8f7f2485059ceb9e7e060bfb72d2a2336807456ae5db125ed1d7a1f6a956c01ec15b364a584340d13141fb678b46fc57eaca7bb2a6ecdabd51653b6276b5b5fc8c515694006ba2aaf7a47c9a3db5a299"))
      val node2: Node = Node(PublicKey(hex"0b8264cd7729b1176032e59a100cf665040a52efaaca004e56544ab7fcdbc4866409f2c3f45dfee38c76a8cb2979b0eb94c9b1b40f4ae5175b48804fa1f20884d0d4cb6320439fab2e0bb9b704babaedf507d20b3d825253244664e46ee315e22fd557ff01a7c5ed7c526183d440bd569c17901ef474f74b7a303284317060e5371f9098521cef77aa256fdbb0695cd8d7e4f231356d3b89"),
        Signature(hex"09a49e0f1485575459dbd7e4d81f364f54c97e80d7b5ad8ab973457ce2715ef67395dfe0674385b13ff029950dce0167e27de4d7ee1af21838408a3b379436ab8ad609132c8644eed6d3dfd9066b77f1a5c0bf1f7131b5a0e066396786493e6432df94339bee3d6db233abdb576a16bb38c6c15c14c9226b6d2617bc985a0ca6c45c1ef401b1dcf08f9527ed0cc2e3905292c1923baa5aac"))
      val node3: Node = Node(PublicKey(hex"006e652c9d42bce989e181037650df9a1f42e81fbfc06defe36dfcf0c1fa9afa7b67cdbab4f52eaf2b13067c1dea97a9b75ee601630ebea9ff77141583204addf179f274a642f4c87f09793b0694a2b611cca1ac933049bfa77fcdfd45a2bfd6dd363adfc82d3d9d74e79ad840b0aa98882045ebc6da9bb03bd7c3c966c14161f8b62678331fabd3d66d2333092a65aa3e73f85dd76f5d5a"),
        Signature(hex"06e2d5ec549dfd84c88b69dbceeac8edbd83fc5e708e2cf9ecea256a03a1ee2f001dce33043c42ad9d8c35fc77b598f86998bd3b96c3df7f8abc8f155974189d3fae54959a996bc0c6d14d63171adbbfeaf9f55f788f20746640be50e4d5f599b27422fc0d8c07ca63b0636c9388c7159106ab51e8ac36eb4057f8be4c9bdd8a3f6f9ea293bb97a6227ed8e192aa1c991223655fbb1628eb")
      )
      val members = List(node1, node2, node3)
      val addrPubPair1=Address(bytes=hex"b10af4dfd065f2b3074aec74ab523b7783bcbb77")->
        PublicKey(bytes=hex"118f521c5f4ff276bdd0185c3d7d8cd75ddaa9a27cef999cd7a98d2136e53d9ce19f07727f80f94d4884fe5a69fbb189f4776bafd5ed1fd6ddf179622a9c07e21362584e0a2b9ad9754faf361627f163d70ac23b0843adb18d2d4b23a0f2a13f7bd193ae7aa98d1d8fa2a0dbff0be1e038c88141facdf76d4f53bf18aaec49db33d22f21dda883b856bde6b7e34aa14af811b684a4762aca")
      val addrSigPair2=Address(bytes=hex"d6fd3f5b5954d0f6cb6f4458f54b1ef723e6f4d2")->
        PublicKey(bytes=hex"0a237dc317e38f4e7e8413297fa18f1d320132a7f917a3dec419b3cb9026626073a7a34586dbe5fe50451684c3f3807c957fbad48fec243fec7a64e43257240b305833a1af133e3aad4874710fed14ac19bbe28f2c115cfe3d7d8fbf63e85047dcd5154c5632354d0deaf22dc5bd04aa08cd102529cd51a07394fe09640a31a260ce30b5df9c325d40a5b2d7f9a8dc117830650e8ef4d160")
      val map=Map.empty+addrPubPair1

      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(group = exchangeGroup.group.copy(members = members,sharePublicKeys =map ))

      exchangeGroupV.verifyGroupFormed shouldBe false
    }

    "report a invalid publicKey list with wrong publicKey " in {
      val node1: Node = Node(random[PublicKey],
        Signature(bytes = hex"044fc52f5504be023c8edcfaaa28d79b8ede3950f9deaf2f47a9b58d147b4bafe2fca7c52f31b0082df4a2fabe7d3e3736e5ae1a99ece704ccbb20a55ef63289b14a9cd00be044be8f7f2485059ceb9e7e060bfb72d2a2336807456ae5db125ed1d7a1f6a956c01ec15b364a584340d13141fb678b46fc57eaca7bb2a6ecdabd51653b6276b5b5fc8c515694006ba2aaf7a47c9a3db5a299"))
      val node2: Node = Node(PublicKey(hex"0b8264cd7729b1176032e59a100cf665040a52efaaca004e56544ab7fcdbc4866409f2c3f45dfee38c76a8cb2979b0eb94c9b1b40f4ae5175b48804fa1f20884d0d4cb6320439fab2e0bb9b704babaedf507d20b3d825253244664e46ee315e22fd557ff01a7c5ed7c526183d440bd569c17901ef474f74b7a303284317060e5371f9098521cef77aa256fdbb0695cd8d7e4f231356d3b89"),
        Signature(hex"09a49e0f1485575459dbd7e4d81f364f54c97e80d7b5ad8ab973457ce2715ef67395dfe0674385b13ff029950dce0167e27de4d7ee1af21838408a3b379436ab8ad609132c8644eed6d3dfd9066b77f1a5c0bf1f7131b5a0e066396786493e6432df94339bee3d6db233abdb576a16bb38c6c15c14c9226b6d2617bc985a0ca6c45c1ef401b1dcf08f9527ed0cc2e3905292c1923baa5aac"))
      val node3: Node = Node(PublicKey(hex"006e652c9d42bce989e181037650df9a1f42e81fbfc06defe36dfcf0c1fa9afa7b67cdbab4f52eaf2b13067c1dea97a9b75ee601630ebea9ff77141583204addf179f274a642f4c87f09793b0694a2b611cca1ac933049bfa77fcdfd45a2bfd6dd363adfc82d3d9d74e79ad840b0aa98882045ebc6da9bb03bd7c3c966c14161f8b62678331fabd3d66d2333092a65aa3e73f85dd76f5d5a"),
        Signature(hex"06e2d5ec549dfd84c88b69dbceeac8edbd83fc5e708e2cf9ecea256a03a1ee2f001dce33043c42ad9d8c35fc77b598f86998bd3b96c3df7f8abc8f155974189d3fae54959a996bc0c6d14d63171adbbfeaf9f55f788f20746640be50e4d5f599b27422fc0d8c07ca63b0636c9388c7159106ab51e8ac36eb4057f8be4c9bdd8a3f6f9ea293bb97a6227ed8e192aa1c991223655fbb1628eb")
      )
      val members = List(node1, node2, node3)
      val addrPubPair1=Address(bytes=hex"b10af4dfd065f2b3074aec74ab523b7783bcbb77")->
        PublicKey(bytes=hex"118f521c5f4ff276bdd0185c3d7d8cd75ddaa9a27cef999cd7a98d2136e53d9ce19f07727f80f94d4884fe5a69fbb189f4776bafd5ed1fd6ddf179622a9c07e21362584e0a2b9ad9754faf361627f163d70ac23b0843adb18d2d4b23a0f2a13f7bd193ae7aa98d1d8fa2a0dbff0be1e038c88141facdf76d4f53bf18aaec49db33d22f21dda883b856bde6b7e34aa14af811b684a4762aca")
      val addrSigPair2=Address(bytes=hex"d6fd3f5b5954d0f6cb6f4458f54b1ef723e6f4d2")->
        PublicKey(bytes=hex"0a237dc317e38f4e7e8413297fa18f1d320132a7f917a3dec419b3cb9026626073a7a34586dbe5fe50451684c3f3807c957fbad48fec243fec7a64e43257240b305833a1af133e3aad4874710fed14ac19bbe28f2c115cfe3d7d8fbf63e85047dcd5154c5632354d0deaf22dc5bd04aa08cd102529cd51a07394fe09640a31a260ce30b5df9c325d40a5b2d7f9a8dc117830650e8ef4d160")
        val map=Map.empty+addrPubPair1+addrSigPair2

      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(group = exchangeGroup.group.copy(members = members,sharePublicKeys =map ))

      exchangeGroupV.verifyGroupFormed shouldBe false
    }

    "report a invalid publicKey list with insufficient length " in {
      val node1: Node = Node(PublicKey(bytes = hex"009df9a83ad9deb35c97f10ae15f455fc37ea00e1ac941afb31587f141452510abd0d74a5b5c442c4ba97d768b703e00cc1cf1e7b17b77d3a3ea29163be4d4c6c9fffbe473b4e0483215454811a2f897513af70ea5eb87c9e65286799ccf4e01e7ec508967a996cf101a659ff9329384ac09d3362c1da73f0253c00deac8beb313acf8753fbfb851c9512f7998de3bd2056340e98a5b5e99"),
        Signature(bytes = hex"044fc52f5504be023c8edcfaaa28d79b8ede3950f9deaf2f47a9b58d147b4bafe2fca7c52f31b0082df4a2fabe7d3e3736e5ae1a99ece704ccbb20a55ef63289b14a9cd00be044be8f7f2485059ceb9e7e060bfb72d2a2336807456ae5db125ed1d7a1f6a956c01ec15b364a584340d13141fb678b46fc57eaca7bb2a6ecdabd51653b6276b5b5fc8c515694006ba2aaf7a47c9a3db5a299"))
      val node2: Node = Node(PublicKey(hex"0b8264cd7729b1176032e59a100cf665040a52efaaca004e56544ab7fcdbc4866409f2c3f45dfee38c76a8cb2979b0eb94c9b1b40f4ae5175b48804fa1f20884d0d4cb6320439fab2e0bb9b704babaedf507d20b3d825253244664e46ee315e22fd557ff01a7c5ed7c526183d440bd569c17901ef474f74b7a303284317060e5371f9098521cef77aa256fdbb0695cd8d7e4f231356d3b89"),
        Signature(hex"09a49e0f1485575459dbd7e4d81f364f54c97e80d7b5ad8ab973457ce2715ef67395dfe0674385b13ff029950dce0167e27de4d7ee1af21838408a3b379436ab8ad609132c8644eed6d3dfd9066b77f1a5c0bf1f7131b5a0e066396786493e6432df94339bee3d6db233abdb576a16bb38c6c15c14c9226b6d2617bc985a0ca6c45c1ef401b1dcf08f9527ed0cc2e3905292c1923baa5aac"))
      val node3: Node = Node(PublicKey(hex"006e652c9d42bce989e181037650df9a1f42e81fbfc06defe36dfcf0c1fa9afa7b67cdbab4f52eaf2b13067c1dea97a9b75ee601630ebea9ff77141583204addf179f274a642f4c87f09793b0694a2b611cca1ac933049bfa77fcdfd45a2bfd6dd363adfc82d3d9d74e79ad840b0aa98882045ebc6da9bb03bd7c3c966c14161f8b62678331fabd3d66d2333092a65aa3e73f85dd76f5d5a"),
        Signature(hex"06e2d5ec549dfd84c88b69dbceeac8edbd83fc5e708e2cf9ecea256a03a1ee2f001dce33043c42ad9d8c35fc77b598f86998bd3b96c3df7f8abc8f155974189d3fae54959a996bc0c6d14d63171adbbfeaf9f55f788f20746640be50e4d5f599b27422fc0d8c07ca63b0636c9388c7159106ab51e8ac36eb4057f8be4c9bdd8a3f6f9ea293bb97a6227ed8e192aa1c991223655fbb1628eb")
      )
      val members = List(node1, node2)
      val addrPubPair1=Address(bytes=hex"b10af4dfd065f2b3074aec74ab523b7783bcbb77")->
        PublicKey(bytes=hex"118f521c5f4ff276bdd0185c3d7d8cd75ddaa9a27cef999cd7a98d2136e53d9ce19f07727f80f94d4884fe5a69fbb189f4776bafd5ed1fd6ddf179622a9c07e21362584e0a2b9ad9754faf361627f163d70ac23b0843adb18d2d4b23a0f2a13f7bd193ae7aa98d1d8fa2a0dbff0be1e038c88141facdf76d4f53bf18aaec49db33d22f21dda883b856bde6b7e34aa14af811b684a4762aca")
      val addrSigPair2=Address(bytes=hex"d6fd3f5b5954d0f6cb6f4458f54b1ef723e6f4d2")->
        PublicKey(bytes=hex"0a237dc317e38f4e7e8413297fa18f1d320132a7f917a3dec419b3cb9026626073a7a34586dbe5fe50451684c3f3807c957fbad48fec243fec7a64e43257240b305833a1af133e3aad4874710fed14ac19bbe28f2c115cfe3d7d8fbf63e85047dcd5154c5632354d0deaf22dc5bd04aa08cd102529cd51a07394fe09640a31a260ce30b5df9c325d40a5b2d7f9a8dc117830650e8ef4d160")
      val map=Map.empty+addrPubPair1+addrSigPair2

      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(group = exchangeGroup.group.copy(members = members,sharePublicKeys =map ))

      exchangeGroupV.verifyGroupFormed shouldBe false
    }

    "report a invalid share Public Key list with wrong share Key " in {
      val node1: Node = Node(PublicKey(bytes = hex"009df9a83ad9deb35c97f10ae15f455fc37ea00e1ac941afb31587f141452510abd0d74a5b5c442c4ba97d768b703e00cc1cf1e7b17b77d3a3ea29163be4d4c6c9fffbe473b4e0483215454811a2f897513af70ea5eb87c9e65286799ccf4e01e7ec508967a996cf101a659ff9329384ac09d3362c1da73f0253c00deac8beb313acf8753fbfb851c9512f7998de3bd2056340e98a5b5e99"),
        Signature(bytes = hex"044fc52f5504be023c8edcfaaa28d79b8ede3950f9deaf2f47a9b58d147b4bafe2fca7c52f31b0082df4a2fabe7d3e3736e5ae1a99ece704ccbb20a55ef63289b14a9cd00be044be8f7f2485059ceb9e7e060bfb72d2a2336807456ae5db125ed1d7a1f6a956c01ec15b364a584340d13141fb678b46fc57eaca7bb2a6ecdabd51653b6276b5b5fc8c515694006ba2aaf7a47c9a3db5a299"))
      val node2: Node = Node(PublicKey(hex"0b8264cd7729b1176032e59a100cf665040a52efaaca004e56544ab7fcdbc4866409f2c3f45dfee38c76a8cb2979b0eb94c9b1b40f4ae5175b48804fa1f20884d0d4cb6320439fab2e0bb9b704babaedf507d20b3d825253244664e46ee315e22fd557ff01a7c5ed7c526183d440bd569c17901ef474f74b7a303284317060e5371f9098521cef77aa256fdbb0695cd8d7e4f231356d3b89"),
        Signature(hex"09a49e0f1485575459dbd7e4d81f364f54c97e80d7b5ad8ab973457ce2715ef67395dfe0674385b13ff029950dce0167e27de4d7ee1af21838408a3b379436ab8ad609132c8644eed6d3dfd9066b77f1a5c0bf1f7131b5a0e066396786493e6432df94339bee3d6db233abdb576a16bb38c6c15c14c9226b6d2617bc985a0ca6c45c1ef401b1dcf08f9527ed0cc2e3905292c1923baa5aac"))
      val node3: Node = Node(PublicKey(hex"006e652c9d42bce989e181037650df9a1f42e81fbfc06defe36dfcf0c1fa9afa7b67cdbab4f52eaf2b13067c1dea97a9b75ee601630ebea9ff77141583204addf179f274a642f4c87f09793b0694a2b611cca1ac933049bfa77fcdfd45a2bfd6dd363adfc82d3d9d74e79ad840b0aa98882045ebc6da9bb03bd7c3c966c14161f8b62678331fabd3d66d2333092a65aa3e73f85dd76f5d5a"),
        Signature(hex"06e2d5ec549dfd84c88b69dbceeac8edbd83fc5e708e2cf9ecea256a03a1ee2f001dce33043c42ad9d8c35fc77b598f86998bd3b96c3df7f8abc8f155974189d3fae54959a996bc0c6d14d63171adbbfeaf9f55f788f20746640be50e4d5f599b27422fc0d8c07ca63b0636c9388c7159106ab51e8ac36eb4057f8be4c9bdd8a3f6f9ea293bb97a6227ed8e192aa1c991223655fbb1628eb")
      )
      val members = List(node1, node2, node3)
      val addrPubPair1=Address(bytes=hex"b10af4dfd065f2b3074aec74ab523b7783bcbb77")->
        random[PublicKey]
      val addrSigPair2=Address(bytes=hex"d6fd3f5b5954d0f6cb6f4458f54b1ef723e6f4d2")->
        PublicKey(bytes=hex"0a237dc317e38f4e7e8413297fa18f1d320132a7f917a3dec419b3cb9026626073a7a34586dbe5fe50451684c3f3807c957fbad48fec243fec7a64e43257240b305833a1af133e3aad4874710fed14ac19bbe28f2c115cfe3d7d8fbf63e85047dcd5154c5632354d0deaf22dc5bd04aa08cd102529cd51a07394fe09640a31a260ce30b5df9c325d40a5b2d7f9a8dc117830650e8ef4d160")
      val map=Map.empty+addrPubPair1+addrSigPair2

      val exchangeGroup = random[ExchangeGroup]
      val exchangeGroupV = exchangeGroup.copy(group = exchangeGroup.group.copy(members = members,sharePublicKeys =map ))

      exchangeGroupV.verifyGroupFormed shouldBe false
    }
  }

  "collectShareKey" should {

    "validate correctly a valid with collected share less than t " in {

    }

    "validate correctly a valid with collected share more than t " in {

    }

    "report a invalid share Key already in collected shares " in {

    }

    "report a invalid with Address who is not in current group " in {

    }

    "report a invalid with wrong secretKey  " in {

    }

    "report a invalid share Public Key list with insufficient length  " in {

    }

    "report a invalid share Public Key list with wrong share Key " in {

    }

  }

  "collectSignatures" should {

    "validate correctly a valid with collected signature share less than t " in {

    }

    "validate correctly a valid with collected signature share more than t " in {

    }

    "report a invalid signature share already in collected shares " in {

    }

    "report a invalid with Address who is not in current group " in {

    }

  }


}
