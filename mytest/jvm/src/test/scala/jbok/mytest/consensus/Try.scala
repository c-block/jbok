package jbok.mytest.consensus

import scala.util.control.NonFatal


abstract class Try[+T]{
  def flatMap[U](f:T=>Try[U]):Try[U]={
    this match {
      case Success(x)=>try f(x) catch{ case NonFatal(ex)=>Fail(ex)}
      case fail:Fail=>fail
    }
  }
  def map[U](f:T=>U):Try[U]={
    this match {
      case Success(x)=>Try(f(x))
      case fail:Fail=>fail
    }
  }
}

case class Success[T](x:T) extends Try[T]
case class Fail(ex:Throwable) extends Try[Nothing]

object Try{
  def apply[T](expr: =>T): Try[T] = {
    try Success(expr)
    catch{
      case NonFatal(ex)=>Fail(ex)
    }
  }
}
