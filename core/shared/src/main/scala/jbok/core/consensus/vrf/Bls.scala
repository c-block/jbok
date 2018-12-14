package jbok.core.consensus.vrf


import jbok.core.models.Address
import scodec.bits.ByteVector
import jbok.crypto._
import it.unisa.dia.gas.jpbc.Element
import it.unisa.dia.gas.jpbc.Pairing
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory
import jbok.core.consensus.vrf.Bls.Signature


case class Rand(bytes: ByteVector) {
  val int: BigInt = BigInt(bytes.toArray)

  // 根据传入的byteVector确定新的 rand
  def DerivedRand(idx: ByteVector): Rand = Rand((bytes ++ idx).kec256)

  // 连接多个string
  def Ders(s: String*): Rand = s.foldLeft(this)((result, str) => result.DerivedRand(ByteVector(str.getBytes)))

  //连接整数
  def Deri(i: Int): Rand = this.Ders(i.toString)

}

trait Bls

object Bls {
  //todo: add resources files
  val pairing: Pairing = PairingFactory.getPairing("bls/a_181_603.properties")
  val systemParameters: Element = pairing.getG2.newRandomElement

  case class SecretKey(bytes: ByteVector) {
    def publicKey: PublicKey = PublicKey(ByteVector(Bls.systemParameters.duplicate().powZn(Bls.getZrElement(bytes.toArray)).toBytes))

    def element: Element = pairing.getZr.newElementFromBytes(bytes.toArray)
  }

  object SecretKey {
    def apply(bytes: Array[Byte]): SecretKey = new SecretKey(ByteVector(bytes))
  }

  case class PublicKey(bytes: ByteVector) {
    val address: Address = Address(bytes.kec256)

    def element: Element = pairing.getG2.newElementFromBytes(bytes.toArray)
  }

  object PublicKey {
    def apply(bytes: Array[Byte]): PublicKey = new PublicKey(ByteVector(bytes))
  }

  case class HashedG1(bytes: ByteVector) {
    def element: Element = pairing.getG1.newElementFromBytes(bytes.toArray)
  }

  case class Signature(bytes: ByteVector) {
    def element: Element = pairing.getG1.newElementFromBytes(bytes.toArray)
  }

  object Signature {
    def apply(bytes: Array[Byte]): Signature = new Signature(ByteVector(bytes))
  }




  /**
    * 1. 得到密钥(bytes) => SecretKey ，Zr域
    */
  def getSecretKey(bytes: ByteVector): SecretKey = SecretKey(bytes)

  /**
    * 2. 得到公钥(SecretKey) =>PublicKey  ,G2 域
    */
  def getPublicKey(bytes: ByteVector): PublicKey = PublicKey(bytes)

  /**
    * 3. 得到G1上的hash值(bytes)=>Hashed , G1域 ,double hash
    */
  def getHashed(bytes: ByteVector): HashedG1 = HashedG1(bytes.kec256.kec256)

  /**
    * 4. 生成签名(Hashed:被签名值,SecretKey:私钥) => Signature ， G1域
    */
  def sign(message: ByteVector, secretKey: SecretKey): Signature = {
    Signature(getHashed(message).element.powZn(secretKey.element).toBytes)
  }

  /**
    * 5. 验证签名(message,Signature,PublicKey) => Boolean
    */
  def verify(message: ByteVector, publicKey: PublicKey, signature: Signature): Boolean = {
    val compactPairing = pairing.pairing(signature.element, systemParameters.duplicate)
    val fullPairing = pairing.pairing(getHashed(message).element, publicKey.element)
    compactPairing.isEqual(fullPairing)
  }

  /**
    * 6. 生成拉格朗日公钥(List<Address>:拉格朗日对应的X轴,List<PublickKey>:拉格朗日对应的Y轴,t：阈值)=>PublicKey
    */
  def lagrangePubkey(addresses: List[Address], publicKeys: List[PublicKey]): PublicKey = PublicKey(bytes = ByteVector.empty)

  /**
    * 7. 生成拉格朗日签名(List<Address>:X轴，List<Signature>：Y轴)=> Signature
    */
  def lagrangeSignature(sigMap: Map[Address, Signature]): Signature =
    Interpolation(sigMap.map(s=>Point(BigInt(s._1.bytes.toArray),BigInt(s._2.bytes.toArray))).toList).intercept


  //10 . 获得G2 元素
  def getG2Element(bytes: Array[Byte]): Element = pairing.getG2.newElementFromBytes(bytes)

  def getG2Element(bigInt: BigInt): Element = getG2Element(bigInt.toByteArray)

  //11 .获得G1 元素
  def getG1Element(bytes: Array[Byte]): Element = pairing.getG1.newElementFromBytes(bytes)

  def getG1Element(bigInt: BigInt): Element = getG1Element(bigInt.toByteArray)

  //12 .获得Zr元素
  def getZrElement(bytes: Array[Byte]): Element = pairing.getZr.newElementFromBytes(bytes)

  def getZrElement(bigInt: BigInt): Element = getZrElement(bigInt.toByteArray)

  def getZrElement(rand: Rand): Element = getZrElement(rand.bytes.toArray)

  def getZrElement(bytes: ByteVector): Element = getZrElement(bytes.toArray)

}

case class Point(x:BigInt,y:BigInt)
case class Interpolation(points:List[Point]) {
  /**
    * 得到拉格朗日求值之后的签名
    */
  def intercept:Signature={
    Signature(
      points.zipWithIndex.foldLeft(Bls.getG1Element(0))((result, p)=>
        result.add(Bls.getG1Element(p._1.y).mul(lagrangeCoefficient(p._2))
    )).toBytes
    )
  }

  def lagrangeCoefficient(i: Int):Element=
    points.zipWithIndex.filter(p => p._2!=i).foldLeft(Bls.getZrElement(1))((result,p)=>
      result.mul(Bls.getZrElement(p._2).div(Bls.getZrElement(p._2).sub(Bls.getZrElement(points(i).x)))))



  def product(xs: List[Element]):Element =
    xs.foldLeft(Bls.getZrElement(1))((result,elem)=>result.mul(elem))

}