package jbok.core.consensus.poa.clique1

import cats.effect.{Async, ConcurrentEffect, Sync}
import jbok.core.models.{Address, BlockHeader}
import jbok.persistent.KeyValueDB
import scalacache.Cache
import scodec.bits.ByteVector
import cats.implicits._
import scalacache.CatsEffect.modes._
import _root_.io.circe.parser._
import jbok.codec.json.implicits._
import Clique._
case class Snapshot(
                     config: CliqueConfig,
                     number: BigInt, // Block number where the snapshot was created
                     hash: ByteVector, // Block hash where the snapshot was created
                     signers: Set[Address], // Set of authorized signers at this moment
                     recents: Map[BigInt, Address] = Map.empty, // Set of recent signers for spam protections
                     votes: List[Vote] = Nil, // List of votes cast in chronological order
                     tally: Map[Address, Tally] = Map.empty // Current vote tally to avoid recalculating
                   ) {

  def clearVotes():Snapshot={
    if(number%config.epoch_length==0){
      copy(votes=Nil,tally=Map.empty)
    }else{
      this
    }
  }
  def deleteRecents():Snapshot={
    val limit = BigInt(signers.size / 2 + 1)
    if (number >= limit) {
      copy(recents = this.recents - (number - limit))
    } else {
      this
    }
  }
  def uncast(address: Address,authorized:Boolean):Snapshot={
    tally.get(address) match {
      case None=>this
      case Some(t) if(t.addOrDrop!=authorized)=>this
      case Some(t)=>
        if(t.numbers>1){
          copy(tally=tally+(address->t.copy(numbers=t.numbers-1)))
        }else{
          copy(tally=tally-address)
        }
    }
  }
  def cast(from:Address,to:Address,authorized:Boolean):Snapshot={
    val dedup=votes.filter(t=>t.from==from&&t.to==to).foldLeft(this)(
      (snap,vote)=>snap.uncast(to,authorized)
    ).copy(votes=votes.filterNot(vote=>vote.from==from&&vote.to==to))

    dedup.signers.contains(to) match {
      case true if authorized=>dedup
      case false if !authorized=>dedup
      case _=>
        val vote=Vote(from,to,authorized,number)
        dedup.tally.contains(to) match {
          case true=>
            val old=dedup.tally(to)
            dedup.copy(
              tally=dedup.tally+(to->old.copy(numbers=old.numbers+1 )),
              votes=dedup.votes++List(vote)
              )
          case false=>
            dedup.copy(tally=dedup.tally+(to->Tally(authorized,1)),
              votes=dedup.votes++List(vote)
            )
        }
    }

  }


}

object Snapshot {
  val namespace = ByteVector("clique".getBytes)

  implicit val snapshotJsonDecoder=deriveDecoder[Snapshot]

  def loadSnapshot[F[_]](db: KeyValueDB[F], hash: ByteVector)(implicit F: Async[F],
                                                              C: Cache[Snapshot]): F[Option[Snapshot]] = {
    C.get[F](hash).flatMap{
      case Some(t)=> Sync[F].pure(Some(t))
      case None =>
          db.getOpt[ByteVector,String](hash,namespace)
            .map(_.map(json=>decode[Snapshot](json).right.get))
            .flatMap{
              case None=> Sync[F].pure(None)
              case Some(snapshot)=>C.put[F](hash)(snapshot).as(Some(snapshot))
            }
    }
  }

  def applyHeaders[F[_]](snapshot: Snapshot,headers:List[BlockHeader])(implicit F:Sync[F]):F[Snapshot]={
    if(headers.isEmpty){
      snapshot.pure[F]
    }else{
      if(
        headers.sliding(2).exists {
          case left::right::Nil=> left.number+1!=right.number
          case _=>false
        }
      )F.raiseError(new Exception("headers must be linked"))
      if(headers.head.number!=snapshot.number+1)
        F.raiseError(new Exception("header in headers must be linked to snapshot"))
      headers.foldLeftM(snapshot)(
        (snap,header)=>{
          val cleared=snap.clearVotes().deleteRecents()
          applyHeader(cleared,header)
        }
      )
    }
  }

  /** create a new snapshot by applying a given header */
  private def applyHeader[F[_]](snap: Snapshot, header: BlockHeader)(implicit F: Sync[F]): F[Snapshot] = F.delay {
    val number=snap.number
    val benifical=Address(header.beneficiary)
    //check whether signer in signers
    val signer=Clique.ecrecover(header)
    if(
      signer.isEmpty|| !snap.signers.contains(signer.get)
    )F.raiseError(new Exception("not authorized signer"))
    //check
    if(snap.recents.exists(_._2==signer))
      F.raiseError(new Exception("can not sign again"))
    val authorized= if(header.nonce==nonceAuthVote){
      true
    }else if(header.nonce==nonceDropVote){
      false
    }else {
      throw new Exception("invalid vote")
    }
    val casted=snap.cast(signer.get,benifical,authorized)

    casted.tally.contains(benifical) match {
      case true=>

    }


  }



}

