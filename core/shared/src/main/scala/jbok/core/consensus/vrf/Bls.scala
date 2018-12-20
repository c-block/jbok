package jbok.core.consensus.vrf


import jbok.core.models.Address
import scodec.bits.ByteVector
import jbok.crypto._
import it.unisa.dia.gas.jpbc.Element
import it.unisa.dia.gas.jpbc.Pairing
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory
import jbok.core.consensus.vrf.Bls.{PublicKey, Signature}


case class Rand(bytes: ByteVector) {
  val int: BigInt = BigInt(bytes.toArray)

  // 根据传入的byteVector确定新的 rand
  def DerivedRand(idx: ByteVector): Rand = Rand((bytes ++ idx).kec256)

  // 连接多个string
  def Ders(s: String*): Rand = s.foldLeft(this)((result, str) => result.DerivedRand(ByteVector(str.getBytes)))

  //连接整数
  def Deri(i: Int): Rand = this.Ders(i.toString)

  //求余
  def modulo(m: Int): Int = int.mod(m).toInt

  //得到一个随机数组,用于分组
  def randPerm(n: Int, k: Int): Array[Int] = {
    val l = (0 until n).toArray
    (0 until k).foreach(i => {
      val j = this.Deri(i).modulo(n - i) + i
      val m = l(i)
      l(i) = l(j)
      l(j) = m
    })
    l.slice(0, k)
  }

}

object Rand {
  def apply(bytes: Array[Byte]): Rand = new Rand(ByteVector(bytes))
}

trait Bls

object Bls {
  val pairing: Pairing = PairingFactory.getPairing("bls/a_181_603.properties")
  val g2: Array[Byte] = ByteVector.fromHex("06BF2B690D3C79EBC7020D59B9A47816806400428E4FD45752B0933F66FD3545" +
    "4FC8F7032A3539B000CB19402E82AC1353F338820F1DEB6402916BFFE0E2CF41B4273D9B8DB151BD9197A2" +
    "3615E0F368017BC09CF8A25343A5DDD8364D522AB639519BD3C0ED1843D77790B6DA1549E93E081042ADD5A5" +
    "502F9D63F1632E52905E17E5077860FB020ADCF3999D1902965D9E94C4B8464023").get.toArray
  val systemParameters: Element = pairing.getG2.newElementFromBytes(g2)

  case class KeyPair(secretKey: SecretKey, publicKey: PublicKey)

  case class SecretKey(bytes: ByteVector) {
    def publicKey: PublicKey = PublicKey(Bls.systemParameters.duplicate().powZn(Bls.getZrElement(bytes.toArray)).toBytes)

    def pop: Signature = Bls.sign(publicKey.bytes, this)

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
    val bytesArr = bytes.toArray

    def element: Element = pairing.getG1.newElementFromHash(bytesArr, 0, bytesArr.length)
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
  def lagrangePublicKey(pubMap: Map[Address, PublicKey]): PublicKey =
    Interpolation(pubMap.map(s => Point((BigInt(s._1.bytes.toArray).abs), (BigInt(s._2.bytes.toArray).abs))).toList).interceptPublicKey

  /**
    * 7. 生成拉格朗日签名(List<Address>:X轴，List<Signature>：Y轴)=> Signature
    */
  def lagrangeSignature(sigMap: Map[Address, Signature]): Signature =
    Interpolation(sigMap.map(s => Point((BigInt(s._1.bytes.toArray).abs), (BigInt(s._2.bytes.toArray).abs))).toList).interceptSignature


  //10 . 获得G2 元素
  def getG2Element(bytes: Array[Byte]): Element = pairing.getG2.newElementFromBytes(bytes)

  def getG2Element(bigInt: BigInt): Element = getG2Element(bigInt.toByteArray)

  def getG2ElementZero: Element = pairing.getG2.newZeroElement

  def getG2ElementOne: Element = pairing.getG2.newOneElement

  //11 .获得G1 元素
  def getG1Element(bytes: Array[Byte]): Element = pairing.getG1.newElementFromBytes(bytes)

  def getG1Element(bigInt: BigInt): Element = getG1Element(bigInt.toByteArray)

  def getG1ElementZero: Element = pairing.getG1.newZeroElement

  //12 .获得Zr元素

  def getZrElement(bytes: Array[Byte]): Element = pairing.getZr.newElementFromBytes(bytes)

  def getZrElement(bigInt: BigInt): Element = getZrElement(bigInt.toByteArray)

  def getZrElement(rand: Rand): Element = getZrElement(rand.bytes.toArray)

  def getZrElement(bytes: ByteVector): Element = getZrElement(bytes.toArray)

  def getZrElementZero: Element = pairing.getZr.newZeroElement

  def getZrElementOne: Element = pairing.getZr.newOneElement

}

case class Point(x: BigInt, y: BigInt)

case class Interpolation(points: List[Point]) {
  /**
    * 得到拉格朗日求值之后的签名
    */
  def interceptSignature: Signature = {
//    val xx=points.map(point=>point.x.toBigInteger.abs->point.y.toBigInteger.abs)
    Signature(
      points.zipWithIndex.foldLeft(Bls.getG1ElementZero)((result, p) =>
        result.add(Bls.getG1Element(p._1.y).mulZn(lagrangeCoefficient(p._2))
        )).toBytes
    )
  }

  def interceptPublicKey: PublicKey = {
    //    val xx=points.map(point=>point.x.toBigInteger.abs->point.y.toBigInteger.abs)
    PublicKey(
      points.zipWithIndex.foldLeft(Bls.getG2ElementZero)((result, p) =>
        result.add(Bls.getG2Element(p._1.y).mulZn(lagrangeCoefficient(p._2))
        )).toBytes
    )
  }

  def lagrangeCoefficient(i: Int): Element = {
    val temp=points.zipWithIndex.filter(p => p._2 != i)
      .map( pair => (Bls.getZrElement(pair._1.x).div(Bls.getZrElement(pair._1.x).sub(Bls.getZrElement(points(i).x)))))
    product(temp)
  }

  def product(xs: List[Element]): Element =
    xs.foldLeft(Bls.getZrElementOne)((result, elem) => result.mul(elem))

}