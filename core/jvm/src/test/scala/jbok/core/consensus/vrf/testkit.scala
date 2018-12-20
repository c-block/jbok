package jbok.core.consensus.vrf

import jbok.core.testkit._
import jbok.common.testkit._
import jbok.core.consensus.vrf.Bls._
import jbok.core.models.Address
import org.scalacheck.{Arbitrary, Gen}

object testkit {

  //生成任意私钥
  implicit val arbSecretKey = Arbitrary[SecretKey] {
    for {
      bytes <- genBoundedByteVector(20, 20)
    } yield SecretKey(bytes)
  }

  implicit val arbAdddress = Arbitrary[Address] {
    for {
      bytes <- genBoundedByteVector(20, 20)
    } yield Address(bytes)
  }

  //生成任意节点
  implicit val arbNode = Arbitrary[Node] {
    for {
      secretKey <- Gen.delay(arbSecretKey.arbitrary)
      pub = secretKey.publicKey
      pop = Bls.sign(pub.bytes, secretKey)
    } yield Node(pub, pop)
  }

  implicit val arbRand = Arbitrary[Rand] {
    for {
      bytes <- genBoundedByteVector(20, 20)
    } yield Rand(bytes)
  }

  implicit val arbGroup :Arbitrary[Group]= Arbitrary{
    for {
      node1 <- arbNode.arbitrary
      node2 <- arbNode.arbitrary
      node3 <- arbNode.arbitrary
      rand1 <- arbRand.arbitrary
    } yield Group(members= List[Node](node1,node2,node3), threshold = 2, rand = rand1)
  }
  implicit val arbExchangeGroup:Arbitrary[ExchangeGroup]= Arbitrary{
    for{
      group<-arbGroup.arbitrary
      secretKey<-arbSecretKey.arbitrary
    } yield ExchangeGroup(group,secretKey)
  }

  implicit val arbRandomBeacon:Arbitrary[RandomBeacon]=Arbitrary{
    for{
      secretKey <- arbSecretKey.arbitrary
    } yield RandomBeacon(secretKey)
  }

  implicit val arbSignature:Arbitrary[Signature]=Arbitrary{
    for{
      bytes <- genBoundedByteVector(152, 152)
    } yield Signature(bytes)
  }

  implicit val arbPublicKey:Arbitrary[PublicKey]=Arbitrary{
    for{
      bytes <- genBoundedByteVector(152, 152)
    } yield PublicKey(bytes)
  }

  implicit val arbMessage:Arbitrary[Message]=Arbitrary{
    for{
      blockHeader <- arbBlockHeader.arbitrary
      sigShare <- arbSignature.arbitrary
      from <- arbAdddress.arbitrary
      sig<- arbSignature.arbitrary
    } yield Message(sigShare,blockHeader,from,sig)
  }

}
