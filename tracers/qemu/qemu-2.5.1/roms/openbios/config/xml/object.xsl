<?xml version="1.0" encoding="ISO-8859-15" ?>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
 
 <!-- wrapper that calls "objects" with parameters -->
 <xsl:template match="/" mode="objects">
  <xsl:call-template name="objects">
   <xsl:with-param name="target" select="'host'"/>
  </xsl:call-template>
  <xsl:call-template name="objects">
   <xsl:with-param name="target" select="'target'"/>
  </xsl:call-template>
 </xsl:template>

 <!-- main work happens here -->
 <xsl:template name="objects">

  <xsl:param name="target"/>
    
  <xsl:text>&#10;#&#10;# </xsl:text>
  <xsl:value-of select="$target"/>
  <xsl:text> compiler rules&#10;#&#10;&#10;</xsl:text>
  
  <!-- create rules for all compile objects -->
  <xsl:for-each select="//object[(ancestor-or-self::*)[@target = $target]]">
  
   <xsl:variable name="path">
    <xsl:for-each select="ancestor::build">
     <xsl:call-template name="get-dirname">
      <xsl:with-param select="@base" name="path"/>
     </xsl:call-template>
    </xsl:for-each>
   </xsl:variable>
     
   <xsl:variable name="conditions">
    <xsl:text>0</xsl:text>
    <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
     <xsl:call-template name="resolve-condition">
      <xsl:with-param select="@condition" name="expression"/>
     </xsl:call-template>
    </xsl:for-each>
   </xsl:variable>
     
   <xsl:if test="$conditions=0">

    <!-- full path of object file -->
    <xsl:text>$(ODIR)/</xsl:text>
    <xsl:value-of select="$target"/>
    <xsl:text>/</xsl:text>
    <xsl:value-of select="$path"/>
    <xsl:value-of select="substring-before(@source,'.')"/>
    <xsl:text>.o: </xsl:text>
 
    <!-- path of source file -->
    <xsl:value-of select="$path"/>
    <xsl:value-of select="@source"/>


    <xsl:choose>
     <xsl:when test="child::rule">
      <xsl:value-of select="child::rule"/>
      <xsl:text>&#10;</xsl:text>
     </xsl:when>
     <xsl:otherwise>
       <xsl:choose>
         <xsl:when test="@flags!=''">
           <xsl:value-of select="document('rules.xml',.)//rule[@target=$target][@entity='object'][@extracflags='1']"/>
           <xsl:text> </xsl:text>
           <xsl:value-of select="@flags"/>
           <xsl:text> </xsl:text>
           <xsl:value-of select="document('rules.xml',.)//rule[@target=$target][@entity='object'][@extracflags='2']"/>
         </xsl:when>
         <xsl:otherwise>
           <!-- FIXME this requires strict spaces in rules.xml -->
           <xsl:value-of select="document('rules.xml',.)//rule[@target=$target][@entity='object']"/>
         </xsl:otherwise>
       </xsl:choose>
     </xsl:otherwise>
    </xsl:choose>
 
   </xsl:if>
  </xsl:for-each>
 
  <!-- Create linker targets for all executables -->
  <xsl:for-each select="//executable">
 
   <xsl:variable name="outer-conditions">
    <xsl:text>0</xsl:text>
    <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
     <xsl:call-template name="resolve-condition">
      <xsl:with-param select="@condition" name="expression"/>
     </xsl:call-template>
    </xsl:for-each>
   </xsl:variable>
   
   <xsl:if test="$outer-conditions = 0">
    <xsl:if test="(ancestor-or-self::*)[@target = $target]">
 
     <!-- executable name -->
     <xsl:text>$(ODIR)/</xsl:text>
     <xsl:value-of select="@name"/>
     <xsl:text>:</xsl:text>
      
     <!-- add all objects -->
     <xsl:for-each select="object">
  
      <xsl:variable name="conditions">
       <xsl:text>0</xsl:text>
       <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
        <xsl:call-template name="resolve-condition">
         <xsl:with-param select="@condition" name="expression"/>
        </xsl:call-template>
       </xsl:for-each>
      </xsl:variable>
      
      <xsl:if test="$conditions=0">
       
       <xsl:variable name="path">
        <xsl:for-each select="ancestor::build">
         <xsl:call-template name="get-dirname">
          <xsl:with-param select="@base" name="path"/>
         </xsl:call-template>
        </xsl:for-each>
       </xsl:variable>
      
       <xsl:text> $(ODIR)/</xsl:text>
       <xsl:value-of select="$target"/>
       <xsl:text>/</xsl:text>
       <xsl:value-of select="$path"/>
       <xsl:value-of select="substring-before(@source,'.')"/>
       <xsl:text>.o</xsl:text>
 
      </xsl:if>
     </xsl:for-each>
 
     <!-- external objects last -->
     <xsl:for-each select="external-object">
 
      <xsl:variable name="conditions">
       <xsl:text>0</xsl:text>
       <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
        <xsl:call-template name="resolve-condition">
         <xsl:with-param select="@condition" name="expression"/>
        </xsl:call-template>
       </xsl:for-each>
      </xsl:variable>
      
      <xsl:if test="$conditions=0">
       <xsl:text> $(ODIR)/</xsl:text>
       <xsl:value-of select="@source"/>
      </xsl:if>
        
     </xsl:for-each>
       
     <!-- print executable rule --> 
     <xsl:choose>
      <xsl:when test="child::rule">
       <xsl:value-of select="child::rule"/>
       <xsl:text>&#10;</xsl:text>
      </xsl:when>
      <xsl:otherwise>
       <!-- FIXME this requires strict spaces in rules.xml -->
       <xsl:value-of select="document('rules.xml',.)//rule[@target=$target][@entity='executable']"/>
      </xsl:otherwise>
     </xsl:choose>
       
    </xsl:if>
   </xsl:if>
  </xsl:for-each>

  <!-- create linker targets for all libs -->
  <xsl:for-each select="//library">
   <xsl:sort select="@name"/>
 
   <xsl:variable name="outer-conditions">
    <xsl:text>0</xsl:text>
    <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
     <xsl:call-template name="resolve-condition">
      <xsl:with-param select="@condition" name="expression"/>
     </xsl:call-template>
    </xsl:for-each>
   </xsl:variable>
   
   <xsl:if test="$outer-conditions = 0">

   
   <xsl:if test="(ancestor-or-self::*)[@target = $target]">
   
    <xsl:if test="not(preceding::library/@name = @name)">
     
     <!-- output library name -->
     <xsl:text>$(ODIR)/lib</xsl:text>
     <xsl:value-of select="@name"/>
	
     <xsl:choose>
      <xsl:when test="@type='static'">
       <xsl:text>.a</xsl:text>
      </xsl:when>
      <xsl:when test="@type='dynamic'">
       <xsl:text>.so</xsl:text>
      </xsl:when>
     </xsl:choose>
     <xsl:text>: </xsl:text>
       
     <xsl:variable name="name"><xsl:value-of select="@name"/></xsl:variable>
       
     <!-- enumerate all objects for library target -->
     <xsl:for-each select="//library[@name=$name]/object">
     
      <xsl:variable name="conditions">
       <xsl:text>0</xsl:text>
       <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
        <xsl:call-template name="resolve-condition">
         <xsl:with-param select="@condition" name="expression"/>
        </xsl:call-template>
       </xsl:for-each>
      </xsl:variable>
     
      <xsl:if test="$conditions=0">
        
       <xsl:variable name="path">
        <xsl:for-each select="ancestor::build">
         <xsl:call-template name="get-dirname">
          <xsl:with-param select="@base" name="path"/>
         </xsl:call-template>
        </xsl:for-each>
       </xsl:variable>
  
       <xsl:text>$(ODIR)/</xsl:text>
       <xsl:value-of select="$target"/>
       <xsl:text>/</xsl:text>
       <xsl:value-of select="$path"/>
       <xsl:value-of select="substring-before(@source,'.')"/>
       <xsl:text>.o </xsl:text>
	
      </xsl:if>
       
     </xsl:for-each>
        
     <!-- external objects last -->
     <xsl:for-each select="external-object">
 
      <xsl:variable name="conditions">
       <xsl:text>0</xsl:text>
       <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
        <xsl:call-template name="resolve-condition">
         <xsl:with-param select="@condition" name="expression"/>
        </xsl:call-template>
       </xsl:for-each>
      </xsl:variable>
      
      <xsl:if test="$conditions=0">
       <xsl:text> $(ODIR)/</xsl:text>
       <xsl:value-of select="@source"/>
      </xsl:if>
        
     </xsl:for-each>
       

     <!-- FIXME this requires strict spaces in rules.xml -->
     <xsl:value-of select="document('rules.xml',.)//rule[@target=$target][@entity='library']"/>
     
    </xsl:if>
   </xsl:if>
   </xsl:if>
  </xsl:for-each>
 
  <!-- create libs rule for all libraries -->
  <xsl:value-of select="$target"/>
  <xsl:text>-libraries: </xsl:text>
  
  <!-- don't build unused libraries
  <xsl:for-each select="//library">
   <xsl:if test="object[(ancestor-or-self::*)[@target = $target]]">
 
    <xsl:variable name="conditions">
     <xsl:text>0</xsl:text>
     <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
      <xsl:call-template name="resolve-condition">
       <xsl:with-param select="@condition" name="expression"/>
      </xsl:call-template>
     </xsl:for-each>
    </xsl:variable>
    <xsl:if test="$conditions=0">
    <xsl:text> $(ODIR)/</xsl:text>
    <xsl:text>lib</xsl:text>
    <xsl:value-of select="@name"/>
     <xsl:choose>
      <xsl:when test="@type='static'">
       <xsl:text>.a</xsl:text>
      </xsl:when>
      <xsl:when test="@type='dynamic'">
       <xsl:text>.so</xsl:text>
      </xsl:when>
     </xsl:choose>
    </xsl:if>
   </xsl:if>
  </xsl:for-each>
  -->
  <xsl:text>&#10;</xsl:text>
  
  <!-- create exe rule for all executables -->
  <xsl:value-of select="$target"/>
  <xsl:text>-executables: </xsl:text>
  
  <xsl:for-each select="//executable">
   <xsl:if test="(ancestor-or-self::*)[@target = $target]">

    <xsl:variable name="conditions">
     <xsl:text>0</xsl:text>
     <xsl:for-each select="(ancestor-or-self::*)[@condition!='']">
      <xsl:call-template name="resolve-condition">
       <xsl:with-param select="@condition" name="expression"/>
      </xsl:call-template>
     </xsl:for-each>
    </xsl:variable>
    <xsl:if test="$conditions=0">
     <xsl:text> $(ODIR)/</xsl:text>
     <xsl:value-of select="@name"/>
    </xsl:if>
   </xsl:if>
  </xsl:for-each>
  <xsl:text>&#10;</xsl:text>
  
 </xsl:template>
 
</xsl:stylesheet>
