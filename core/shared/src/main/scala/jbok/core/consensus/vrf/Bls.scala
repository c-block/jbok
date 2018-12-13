package jbok.core.consensus.vrf


import jbok.core.models.Address
import scodec.bits.ByteVector
import jbok.crypto._
import it.unisa.dia.gas.jpbc.Element
import it.unisa.dia.gas.jpbc.Pairing
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory


case class Rand(bytes:ByteVector){
  val int:BigInt=BigInt(bytes.toArray)
  // 根据传入的byteVector确定新的 rand
  def DerivedRand(idx: ByteVector): Rand = Rand((bytes++idx).kec256)

  // 连接多个string
  def Ders(s: String*): Rand = s.foldLeft(this)((result,str)=>(result.DerivedRand(ByteVector(str.getBytes))))

  //连接整数
  def Deri(i: Int): Rand =this.Ders(i.toString)

}
case class SecretKey(bytes:ByteVector){
  val publicKey:PublicKey=PublicKey(ByteVector(Bls.systemParameters.duplicate().powZn(Bls.getZrElement(bytes.toArray)).toBytes))
}
object SecretKey{
  def apply(bytes: Array[Byte]): SecretKey = new SecretKey(ByteVector(bytes))
}
case class PublicKey(bytes:ByteVector){
  val address:Address= Address(bytes.kec256)
}
object PublicKey{
  def apply(bytes: Array[Byte]): PublicKey = new PublicKey(ByteVector(bytes))
}
case class HashedG1(bytes:ByteVector)
case class Signature(bytes:ByteVector)

trait Bls

object Bls{
  //todo: add resources files
  val pairing:Pairing=PairingFactory.getPairing("it/unisa/dia/gas/plaf/jpbc/pairing/a/a_181_603.properties")
  val systemParameters:Element= pairing.getG2.newRandomElement

  /**
    * 1. 得到密钥(bytes) => SecretKey ，Zr域
    */
  def getSecretKey(bytes:ByteVector):SecretKey=SecretKey(bytes=ByteVector.empty)

  /**
    * 2. 得到公钥(SecretKey) =>PublicKey  ,G2 域
    */
  def getPublicKey(secretKey: SecretKey):PublicKey=PublicKey(bytes = ByteVector.empty)

  /**
    * 3. 得到G1上的hash值(bytes)=>Hashed , G1域
    */
  def getHashed(bytes:ByteVector):HashedG1=HashedG1(bytes=ByteVector.empty)

  /**
    * 4. 生成签名(Hashed:被签名值,SecretKey:私钥) => Signature ， G1域
    */
  def sign(hashedG1: HashedG1, secretKey: SecretKey):Signature=Signature(bytes = ByteVector.empty)

  /**
    * 5. 验证签名(Hashed,Signature,PublicKey) => Boolean
    */
  def verify(hashedG1: HashedG1, publicKey: PublicKey, signature: Signature):Boolean=true

  /**
    * 6. 生成拉格朗日公钥(List<Address>:拉格朗日对应的X轴,List<PublickKey>:拉格朗日对应的Y轴,t：阈值)=>PublicKey
    */
  def lagrangePubkey(addresses:List[Address],publicKeys:List[PublicKey]):PublicKey=PublicKey(bytes = ByteVector.empty)

  /**
    * 7. 生成拉格朗日签名(List<Address>:X轴，List<Signature>：Y轴)=> Signature
    */
  def lagrangeSignature(addresses:List[Address],signatures:List[Signature]):Signature=Signature(bytes = ByteVector.empty)

  /**
    * 8. 公钥相乘(List[PublicKey]) : PublicKey
    */
  def mulPublicKeys(publicKeys: List[PublicKey]):PublicKey=PublicKey(bytes =  ByteVector.empty)

  /**
    * 9. 私钥想加(List[SecretKey]): SecretKey
    */
  def addSecretKeys(secretKeys: List[SecretKey]) :SecretKey =SecretKey(ByteVector.empty)

  //10 . 获得G2 元素
  def getG2Element(bytes:Array[Byte]):Element=pairing.getG2.newElementFromBytes(bytes)
  def getG2Element(bigInt: BigInt):Element=getG2Element(bigInt.toByteArray)

  //11 .获得G1 元素
  def getG1Element(bytes:Array[Byte]):Element=pairing.getG1.newElementFromBytes(bytes)
  def getG1Element(bigInt: BigInt):Element=getG1Element(bigInt.toByteArray)

  //12 .获得Zr元素
  def getZrElement(bytes:Array[Byte]) :Element =pairing.getZr.newElementFromBytes(bytes)
  def getZrElement(bigInt: BigInt) :Element =getZrElement(bigInt.toByteArray)
  def getZrElement(rand: Rand):Element=getZrElement(rand.bytes.toArray)
  def getZrElement(bytes:ByteVector):Element = getZrElement(bytes.toArray)

}