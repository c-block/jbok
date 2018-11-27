package jbok.mytest.consensus

import cats._
import cats.implicits._

object intOrdering extends Ordering[Int]{
  override def compare(x: Int, y: Int): Int = {
    if(x<y) 1
    else if(x==y) 0
    else -1
  }
}

object MergeSort {
  def msort[T](xs:List[T])(ord:Ordering[T]):List[T]={
    val n=xs.length/2
    if (n==0) xs
    else {
      def merge(xs:List[T],ys:List[T]):List[T]=(xs,ys) match {
        case (Nil,ys)=>ys
        case (xs,Nil)=>xs
        case (x1::xs1,y1::ys1)=>{
          if(ord.lt(x1,y1)) x1::merge(xs1,ys)
          else y1::merge(xs,ys1)
        }
      }
      val (fst,snd)=xs splitAt n
      merge(msort(fst)(ord),msort(snd)(ord))
    }
  }

  def main(args: Array[String]): Unit = {
    val nums=List(9,4,-5,11)

    print(msort(nums)(intOrdering))

    Monoid[String].combine("hi","streamye")
   List(1,2,3) >>= (x=>List(x+1))
   val a= Functor[List].lift((x:Int)=>x+1)
    println(a(List(1)))
  }
}

//trait Monoid[A] {
//  def mempty: A
//  def mappend(a: A, b: A): A
//}
//object Monoid{
//  implicit object IntMonoid extends Monoid[Int] {
//    override def mempty = 0
//    override def mappend(a: Int, b: Int) = a + b
//  }
//  implicit object StringMonoid extends Monoid[String] {
//    override def mempty = ""
//    override def mappend(a: String, b: String) = a + b
//  }
//  def mconcat[A](xs: List[A])(implicit monoid: Monoid[A]): A = {
//    xs.foldLeft(monoid.mempty)(monoid.mappend)
//  }
//  def mconcat[A : Monoid](xs: List[A]): A = {
//    val monoid = implicitly[Monoid[A]]
//    xs.foldLeft(monoid.mempty)(monoid.mappend)
//  }
//  def main(args: Array[String]): Unit = {
//    println(mconcat(List(1,2,3,4)))
//  }
//}
//

sealed trait Json
case class JsObject(get:Map[String,Json]) extends Json
case class JsString(get:String) extends Json
case class JsNumber(get:Double) extends Json
trait JsonWriter[A]{
  def write(value:A):Json
}
case class Person(name:String,email:String)
//这里定义了type class instances
object JsonWriterInstances{
  implicit val stringJsonWriter:JsonWriter[String]=new JsonWriter[String] {
    override def write(value: String) = JsString(value)
  }
  implicit val personJsonWriter:JsonWriter[Person]=new JsonWriter[Person] {
    override def write(value: Person) = JsObject(Map(
      "name"->JsString(value.name),
      "email"->JsString(value.email)
    ))
  }
}
object Json{
  def toJson[A](value:A)(implicit w:JsonWriter[A]):Json=w.write(value)
}

object JsonSyntax{
  implicit class JsonWriterOps[A](value:A){
    def toJson(implicit w:JsonWriter[A]):Json=w.write(value)
  }
}

object kk{
  import JsonWriterInstances._
  import JsonSyntax.JsonWriterOps

  def main(args: Array[String]): Unit = {
    println(Json.toJson(Person("hang","hangscer@gmail.com")))
    val r1=Person("hang","email").toJson
    val r2="haha".toJson
    cats.syntax.show.toShow()
  }

}
