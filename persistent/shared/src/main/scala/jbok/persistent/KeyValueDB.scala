package jbok.persistent

import cats.data.OptionT
import cats.effect.Sync
import cats.implicits._
import scodec.Codec
import scodec.bits.ByteVector

abstract class KeyValueDB[F[_]](implicit F: Sync[F]) {
  protected[jbok] def getRaw(key: ByteVector): F[Option[ByteVector]]

  protected[jbok] def putRaw(key: ByteVector, newVal: ByteVector): F[Unit]

  protected[jbok] def delRaw(key: ByteVector): F[Unit]

  protected[jbok] def hasRaw(key: ByteVector): F[Boolean]

  protected[jbok] def keysRaw: F[List[ByteVector]]

  protected[jbok] def size: F[Int]

  protected[jbok] def toMapRaw: F[Map[ByteVector, ByteVector]]

  protected[jbok] def writeBatchRaw(put: List[(ByteVector, ByteVector)], del: List[ByteVector]): F[Unit]

  def keys[Key: Codec](namespace: ByteVector): F[List[Key]]

  def toMap[Key: Codec, Val: Codec](namespace: ByteVector): F[Map[Key, Val]]

  final def getOpt[Key: Codec, Val: Codec](key: Key, namespace: ByteVector): F[Option[Val]] =
    for {
      rawkey <- encode[Key](key, namespace)
      rawval <- getRaw(rawkey)
      v      <- rawval.fold(none[Val].pure[F])(x => decode[Val](x).map(_.some))
    } yield v

  final def getOptT[Key: Codec, Val: Codec](key: Key, namespace: ByteVector): OptionT[F, Val] =
    OptionT(getOpt[Key, Val](key, namespace))

  final def get[Key: Codec, Val: Codec](key: Key, namespace: ByteVector): F[Val] =
    getOpt[Key, Val](key, namespace).map(_.get)

  final def put[Key: Codec, Val: Codec](key: Key, newVal: Val, namespace: ByteVector): F[Unit] =
    for {
      rawkey <- encode[Key](key, namespace)
      rawval <- encode[Val](newVal)
      _      <- putRaw(rawkey, rawval)
    } yield ()

  final def del[Key: Codec](key: Key, namespace: ByteVector): F[Unit] =
    for {
      rawK <- encode[Key](key, namespace)
      _    <- delRaw(rawK)
    } yield ()

  final def has[Key: Codec](key: Key, namespace: ByteVector): F[Boolean] =
    encode[Key](key, namespace) >>= hasRaw

  final def writeBatch[Key: Codec, Val: Codec](put: List[(Key, Val)], del: List[Key], namespace: ByteVector): F[Unit] =
    for {
      p <- put.traverse { case (k, v) => (encode[Key](k, namespace), encode[Val](v)).tupled }
      d <- del.traverse(k => encode[Key](k, namespace))
      _ <- writeBatchRaw(p, d)
    } yield ()

  final def writeBatch[Key: Codec, Val: Codec](ops: List[(Key, Option[Val])], namespace: ByteVector): F[Unit] = {
    val (a, b) = ops.partition(_._2.isDefined)
    val put    = a.map { case (k, v) => k -> v.get }
    val del    = b.map { case (k, _) => k }
    writeBatch[Key, Val](put, del, namespace)
  }

  def encode[A: Codec](a: A, prefix: ByteVector = ByteVector.empty): F[ByteVector] =
    F.delay(prefix ++ Codec[A].encode(a).require.bytes)

  def decode[A: Codec](bytes: ByteVector, prefix: ByteVector = ByteVector.empty): F[A] =
    F.delay(Codec[A].decode(bytes.drop(prefix.length).bits).require.value)
}

object KeyValueDB extends KeyValueDBPlatform {
  val INMEM = "inmem"

  def inmem[F[_]: Sync]: F[KeyValueDB[F]] = InmemKeyValueDB[F]

  def forPath[F[_]: Sync](path: String): F[KeyValueDB[F]] = _forPath[F](path)
}