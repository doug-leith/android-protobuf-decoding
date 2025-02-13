# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: document_v2.proto
# Protobuf Python Version: 4.25.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import doc_details_pb2 as doc__details__pb2
import rating_pb2 as rating__pb2
import doc_annotations_pb2 as doc__annotations__pb2
import common_pb2 as common__pb2
import plus_data_pb2 as plus__data__pb2
import video_doc_annotations_pb2 as video__doc__annotations__pb2
import filter_rules_pb2 as filter__rules__pb2
import containers_pb2 as containers__pb2
import tip_pb2 as tip__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x11\x64ocument_v2.proto\x12\nDocumentV2\x1a\x11\x64oc_details.proto\x1a\x0crating.proto\x1a\x15\x64oc_annotations.proto\x1a\x0c\x63ommon.proto\x1a\x0fplus_data.proto\x1a\x1bvideo_doc_annotations.proto\x1a\x12\x66ilter_rules.proto\x1a\x10\x63ontainers.proto\x1a\ttip.proto\"\x15\n\x13\x41vatarCardContainer\"&\n\x0e\x45mptyContainer\x12\x14\n\x0c\x65mptyMessage\x18\x01 \x01(\t\"\x18\n\x16\x41rtistClusterContainer\";\n\x11WideCardContainer\x12\x10\n\x08rowCount\x18\x01 \x01(\x05\x12\x14\n\x0cshowOrdinals\x18\x02 \x01(\x08\"1\n\tDismissal\x12\x0b\n\x03url\x18\x01 \x01(\t\x12\x17\n\x0f\x64\x65scriptionHtml\x18\x02 \x01(\t\"X\n\x0fOBSOLETE_Reason\x12\x13\n\x0b\x62riefReason\x18\x01 \x01(\t\x12\x1e\n\x16oBSOLETEDetailedReason\x18\x02 \x01(\t\x12\x10\n\x08uniqueId\x18\x03 \x01(\t\"\xbe\x01\n\x18\x45\x64itorialSeriesContainer\x12\x13\n\x0bseriesTitle\x18\x01 \x01(\t\x12\x16\n\x0eseriesSubtitle\x18\x02 \x01(\t\x12\x14\n\x0c\x65pisodeTitle\x18\x03 \x01(\t\x12\x17\n\x0f\x65pisodeSubtitle\x18\x04 \x01(\t\x12\x16\n\x0e\x63olorThemeArgb\x18\x05 \x01(\t\x12.\n\x0cvideoSnippet\x18\x06 \x03(\x0b\x32\x18.DocumentV2.VideoSnippet\"-\n\x13\x43ontainerWithBanner\x12\x16\n\x0e\x63olorThemeArgb\x18\x01 \x01(\t\"\xf3\x01\n\rSeriesAntenna\x12\x13\n\x0bseriesTitle\x18\x01 \x01(\t\x12\x16\n\x0eseriesSubtitle\x18\x02 \x01(\t\x12\x14\n\x0c\x65pisodeTitle\x18\x03 \x01(\t\x12\x17\n\x0f\x65pisodeSubtitle\x18\x04 \x01(\t\x12\x16\n\x0e\x63olorThemeArgb\x18\x05 \x01(\t\x12\x36\n\rsectionTracks\x18\x06 \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12\x36\n\rsectionAlbums\x18\x07 \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\"\xac\x0f\n\x08Template\x12\x30\n\rseriesAntenna\x18\x01 \x01(\x0b\x32\x19.DocumentV2.SeriesAntenna\x12\x30\n\x0etileGraphic2X1\x18\x02 \x01(\x0b\x32\x18.DocumentV2.TileTemplate\x12\x30\n\x0etileGraphic4X2\x18\x03 \x01(\x0b\x32\x18.DocumentV2.TileTemplate\x12<\n\x1atileGraphicColoredTitle2X1\x18\x04 \x01(\x0b\x32\x18.DocumentV2.TileTemplate\x12>\n\x1ctileGraphicUpperLeftTitle2X1\x18\x05 \x01(\x0b\x32\x18.DocumentV2.TileTemplate\x12@\n\x1etileDetailsReflectedGraphic2X2\x18\x06 \x01(\x0b\x32\x18.DocumentV2.TileTemplate\x12\x32\n\x10tileFourBlock4X2\x18\x07 \x01(\x0b\x32\x18.DocumentV2.TileTemplate\x12<\n\x13\x63ontainerWithBanner\x18\x08 \x01(\x0b\x32\x1f.DocumentV2.ContainerWithBanner\x12.\n\x0c\x64\x65\x61lOfTheDay\x18\t \x01(\x0b\x32\x18.DocumentV2.DealOfTheDay\x12<\n\x1atileGraphicColoredTitle4X2\x18\n \x01(\x0b\x32\x18.DocumentV2.TileTemplate\x12\x46\n\x18\x65\x64itorialSeriesContainer\x18\x0b \x01(\x0b\x32$.DocumentV2.EditorialSeriesContainer\x12\x46\n\x18recommendationsContainer\x18\x0c \x01(\x0b\x32$.DocumentV2.RecommendationsContainer\x12*\n\nnextBanner\x18\r \x01(\x0b\x32\x16.DocumentV2.NextBanner\x12\x30\n\rrateContainer\x18\x0e \x01(\x0b\x32\x19.DocumentV2.RateContainer\x12@\n\x15\x61\x64\x64ToCirclesContainer\x18\x0f \x01(\x0b\x32!.DocumentV2.AddToCirclesContainer\x12\x42\n\x16trustedSourceContainer\x18\x10 \x01(\x0b\x32\".DocumentV2.TrustedSourceContainer\x12\x44\n\x17rateAndSuggestContainer\x18\x11 \x01(\x0b\x32#.DocumentV2.RateAndSuggestContainer\x12.\n\x0c\x61\x63tionBanner\x18\x12 \x01(\x0b\x32\x18.DocumentV2.ActionBanner\x12,\n\x0bwarmWelcome\x18\x13 \x01(\x0b\x32\x17.DocumentV2.WarmWelcome\x12Z\n\"recommendationsContainerWithHeader\x18\x14 \x01(\x0b\x32..DocumentV2.RecommendationsContainerWithHeader\x12\x32\n\x0e\x65mptyContainer\x18\x15 \x01(\x0b\x32\x1a.DocumentV2.EmptyContainer\x12:\n\x12myCirclesContainer\x18\x16 \x01(\x0b\x32\x1e.DocumentV2.MyCirclesContainer\x12<\n\x13singleCardContainer\x18\x17 \x01(\x0b\x32\x1f.DocumentV2.SingleCardContainer\x12\x42\n\x16moreByCreatorContainer\x18\x18 \x01(\x0b\x32\".DocumentV2.MoreByCreatorContainer\x12\x46\n\x18purchaseHistoryContainer\x18\x19 \x01(\x0b\x32$.DocumentV2.PurchaseHistoryContainer\x12\x1e\n\x04snow\x18\x1a \x01(\x0b\x32\x10.DocumentV2.Snow\x12\x38\n\x11multiRowContainer\x18\x1c \x01(\x0b\x32\x1d.DocumentV2.MultiRowContainer\x12\x38\n\x11wideCardContainer\x18\x1d \x01(\x0b\x32\x1d.DocumentV2.WideCardContainer\x12<\n\x13\x61vatarCardContainer\x18\x1e \x01(\x0b\x32\x1f.DocumentV2.AvatarCardContainer\x12.\n\x0c\x62undleBanner\x18\x1f \x01(\x0b\x32\x18.DocumentV2.BundleBanner\x12\x34\n\x0f\x62undleContainer\x18  \x01(\x0b\x32\x1b.DocumentV2.BundleContainer\x12@\n\x15\x66\x65\x61turedAppsContainer\x18! \x01(\x0b\x32!.DocumentV2.FeaturedAppsContainer\x12\x42\n\x16\x61rtistClusterContainer\x18\" \x01(\x0b\x32\".DocumentV2.ArtistClusterContainer\"P\n\x0cVideoSnippet\x12\x1c\n\x05image\x18\x01 \x03(\x0b\x32\r.Common.Image\x12\r\n\x05title\x18\x02 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x03 \x01(\t\"7\n\x0bWarmWelcome\x12(\n\x06\x61\x63tion\x18\x01 \x03(\x0b\x32\x18.DocumentV2.CallToAction\"\x17\n\x15\x41\x64\x64ToCirclesContainer\">\n\x0c\x44\x65\x61lOfTheDay\x12\x16\n\x0e\x66\x65\x61turedHeader\x18\x01 \x01(\t\x12\x16\n\x0e\x63olorThemeArgb\x18\x02 \x01(\t\"\xaa\r\n\x0b\x41nnotations\x12\x37\n\x0esectionRelated\x18\x01 \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12\x36\n\rsectionMoreBy\x18\x02 \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12,\n\x0bplusOneData\x18\x03 \x01(\x0b\x32\x17.DocumentV2.PlusOneData\x12(\n\x07warning\x18\x04 \x03(\x0b\x32\x17.DocAnnotations.Warning\x12:\n\x11sectionBodyOfWork\x18\x05 \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12;\n\x12sectionCoreContent\x18\x06 \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12&\n\x08template\x18\x07 \x01(\x0b\x32\x14.DocumentV2.Template\x12.\n\x0f\x62\x61\x64geForCreator\x18\x08 \x03(\x0b\x32\x15.DocAnnotations.Badge\x12*\n\x0b\x62\x61\x64geForDoc\x18\t \x03(\x0b\x32\x15.DocAnnotations.Badge\x12\"\n\x04link\x18\n \x01(\x0b\x32\x14.DocAnnotations.Link\x12\x39\n\x10sectionCrossSell\x18\x0b \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12>\n\x15sectionRelatedDocType\x18\x0c \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12\x30\n\x0bpromotedDoc\x18\r \x03(\x0b\x32\x1b.DocAnnotations.PromotedDoc\x12\x11\n\tofferNote\x18\x0e \x01(\t\x12\'\n\x0csubscription\x18\x10 \x03(\x0b\x32\x11.DocumentV2.DocV2\x12\x33\n\x0eoBSOLETEReason\x18\x11 \x01(\x0b\x32\x1b.DocumentV2.OBSOLETE_Reason\x12\x18\n\x10privacyPolicyUrl\x18\x12 \x01(\t\x12\x38\n\x11suggestionReasons\x18\x13 \x01(\x0b\x32\x1d.DocumentV2.SuggestionReasons\x12:\n\x19optimalDeviceClassWarning\x18\x14 \x01(\x0b\x32\x17.DocAnnotations.Warning\x12\x39\n\x11\x64ocBadgeContainer\x18\x15 \x03(\x0b\x32\x1e.DocAnnotations.BadgeContainer\x12@\n\x17sectionSuggestForRating\x18\x16 \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12\x41\n\x18sectionPurchaseCrossSell\x18\x18 \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12.\n\x0coverflowLink\x18\x19 \x03(\x0b\x32\x18.DocumentV2.OverflowLink\x12%\n\ncreatorDoc\x18\x1a \x01(\x0b\x32\x11.DocumentV2.DocV2\x12\x17\n\x0f\x61ttributionHtml\x18\x1b \x01(\t\x12\x46\n\x16purchaseHistoryDetails\x18\x1c \x01(\x0b\x32&.DocAnnotations.PurchaseHistoryDetails\x12\x34\n\x15\x62\x61\x64geForContentRating\x18\x1d \x01(\x0b\x32\x15.DocAnnotations.Badge\x12,\n\x0bvoucherInfo\x18\x1e \x03(\x0b\x32\x17.DocumentV2.VoucherInfo\x12<\n\x13sectionFeaturedApps\x18  \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12$\n\x1c\x61pplicableVoucherDescription\x18! \x01(\t\x12;\n\x12\x64\x65tailsPageCluster\x18\" \x03(\x0b\x32\x1f.DocAnnotations.SectionMetadata\x12?\n\x10videoAnnotations\x18# \x01(\x0b\x32%.VideoDocAnnotations.VideoAnnotations\x12\x45\n\x1csectionPurchaseRelatedTopics\x18$ \x01(\x0b\x32\x1f.DocAnnotations.SectionMetadata\"\x1a\n\x18PurchaseHistoryContainer\"\x0f\n\rRateContainer\"2\n\x0cReasonReview\x12\"\n\x06review\x18\x01 \x01(\x0b\x32\x12.DocumentV2.Review\"\x9a\x01\n\x11SuggestionReasons\x12\"\n\x06reason\x18\x02 \x03(\x0b\x32\x12.DocumentV2.Reason\x12/\n\x10neutralDismissal\x18\x04 \x01(\x0b\x32\x15.DocumentV2.Dismissal\x12\x30\n\x11positiveDismissal\x18\x05 \x01(\x0b\x32\x15.DocumentV2.Dismissal\"\xd8\x06\n\x05\x44ocV2\x12\r\n\x05\x64ocid\x18\x01 \x01(\t\x12\x14\n\x0c\x62\x61\x63kendDocid\x18\x02 \x01(\t\x12\x0f\n\x07\x64ocType\x18\x03 \x01(\x05\x12\x11\n\tbackendId\x18\x04 \x01(\x05\x12\r\n\x05title\x18\x05 \x01(\t\x12\x0f\n\x07\x63reator\x18\x06 \x01(\t\x12\x17\n\x0f\x64\x65scriptionHtml\x18\x07 \x01(\t\x12\x1c\n\x05offer\x18\x08 \x03(\x0b\x32\r.Common.Offer\x12/\n\x0c\x61vailability\x18\t \x01(\x0b\x32\x19.FilterRules.Availability\x12\x1c\n\x05image\x18\n \x03(\x0b\x32\r.Common.Image\x12 \n\x05\x63hild\x18\x0b \x03(\x0b\x32\x11.DocumentV2.DocV2\x12\x38\n\x11\x63ontainerMetadata\x18\x0c \x01(\x0b\x32\x1d.Containers.ContainerMetadata\x12,\n\x07\x64\x65tails\x18\r \x01(\x0b\x32\x1b.DocDetails.DocumentDetails\x12\x30\n\x0f\x61ggregateRating\x18\x0e \x01(\x0b\x32\x17.Rating.AggregateRating\x12,\n\x0b\x61nnotations\x18\x0f \x01(\x0b\x32\x17.DocumentV2.Annotations\x12\x12\n\ndetailsUrl\x18\x10 \x01(\t\x12\x10\n\x08shareUrl\x18\x11 \x01(\t\x12\x12\n\nreviewsUrl\x18\x12 \x01(\t\x12\x12\n\nbackendUrl\x18\x13 \x01(\t\x12\x1a\n\x12purchaseDetailsUrl\x18\x14 \x01(\t\x12\x17\n\x0f\x64\x65tailsReusable\x18\x15 \x01(\x08\x12\x10\n\x08subtitle\x18\x16 \x01(\t\x12!\n\x19translatedDescriptionHtml\x18\x17 \x01(\t\x12\x18\n\x10serverLogsCookie\x18\x18 \x01(\x0c\x12\x32\n\x0eproductDetails\x18\x19 \x01(\x0b\x32\x1a.DocDetails.ProductDetails\x12\x0e\n\x06mature\x18\x1a \x01(\x08\x12\x1e\n\x16promotionalDescription\x18\x1b \x01(\t\x12#\n\x1b\x61vailableForPreregistration\x18\x1d \x01(\x08\x12\x1b\n\x03tip\x18\x1e \x03(\x0b\x32\x0e.Tip.ReviewTip\"\xe5\x01\n\x06Reason\x12\x17\n\x0f\x64\x65scriptionHtml\x18\x03 \x01(\t\x12\x30\n\rreasonPlusOne\x18\x04 \x01(\x0b\x32\x19.DocumentV2.ReasonPlusOne\x12.\n\x0creasonReview\x18\x05 \x01(\x0b\x32\x18.DocumentV2.ReasonReview\x12(\n\tdismissal\x18\x07 \x01(\x0b\x32\x15.DocumentV2.Dismissal\x12\x36\n\x10reasonUserAction\x18\t \x01(\x0b\x32\x1c.DocumentV2.ReasonUserAction\"A\n\x04Snow\x12\x10\n\x08\x63lickUrl\x18\x01 \x01(\t\x12\x10\n\x08snowText\x18\x02 \x01(\t\x12\x15\n\rsnowBadgeText\x18\x03 \x01(\t\"\x15\n\x13SingleCardContainer\"D\n\nNextBanner\x12\r\n\x05title\x18\x01 \x01(\t\x12\x10\n\x08subtitle\x18\x02 \x01(\t\x12\x15\n\rcolorTextArgb\x18\x03 \x01(\t\"\x8a\x01\n\x0c\x41\x63tionBanner\x12(\n\x06\x61\x63tion\x18\x01 \x03(\x0b\x32\x18.DocumentV2.CallToAction\x12&\n\x0bprimaryFace\x18\x02 \x01(\x0b\x32\x11.DocumentV2.DocV2\x12(\n\rsecondaryFace\x18\x04 \x03(\x0b\x32\x11.DocumentV2.DocV2\"\xad\x03\n\x06Review\x12\x12\n\nauthorName\x18\x01 \x01(\t\x12\x0b\n\x03url\x18\x02 \x01(\t\x12\x0e\n\x06source\x18\x03 \x01(\t\x12\x17\n\x0f\x64ocumentVersion\x18\x04 \x01(\t\x12\x15\n\rtimestampMsec\x18\x05 \x01(\x03\x12\x12\n\nstarRating\x18\x06 \x01(\x05\x12\r\n\x05title\x18\x07 \x01(\t\x12\x0f\n\x07\x63omment\x18\x08 \x01(\t\x12\x11\n\tcommentId\x18\t \x01(\t\x12\x12\n\ndeviceName\x18\x13 \x01(\t\x12\x11\n\treplyText\x18\x1d \x01(\t\x12\x1a\n\x12replyTimestampMsec\x18\x1e \x01(\x03\x12;\n\x13oBSOLETEPlusProfile\x18\x1f \x01(\x0b\x32\x1e.PlusData.OBSOLETE_PlusProfile\x12!\n\x06\x61uthor\x18! \x01(\x0b\x32\x11.DocumentV2.DocV2\x12 \n\tsentiment\x18\" \x01(\x0b\x32\r.Common.Image\x12\x14\n\x0chelpfulCount\x18# \x01(\x05\x12\x10\n\x08tipStart\x18$ \x03(\x05\x12\x0e\n\x06tipEnd\x18% \x03(\x05\"\x14\n\x12MyCirclesContainer\"\x11\n\x0f\x42undleContainer\"8\n\x0c\x42undleBanner\x12(\n\x06\x61\x63tion\x18\x01 \x03(\x0b\x32\x18.DocumentV2.CallToAction\"\x1a\n\x18RecommendationsContainer\"=\n\x0cTileTemplate\x12\x16\n\x0e\x63olorThemeArgb\x18\x01 \x01(\t\x12\x15\n\rcolorTextArgb\x18\x02 \x01(\t\"W\n\x10ReasonUserAction\x12!\n\x06person\x18\x01 \x01(\x0b\x32\x11.DocumentV2.DocV2\x12 \n\x18localizedDescriptionHtml\x18\x02 \x01(\t\"K\n\x0bVoucherInfo\x12\x1e\n\x03\x64oc\x18\x01 \x01(\x0b\x32\x11.DocumentV2.DocV2\x12\x1c\n\x05offer\x18\x02 \x03(\x0b\x32\r.Common.Offer\"%\n\x11MultiRowContainer\x12\x10\n\x08rowCount\x18\x01 \x01(\x05\"\x91\x01\n\rReasonPlusOne\x12 \n\x18localizedDescriptionHtml\x18\x01 \x01(\t\x12;\n\x13oBSOLETEPlusProfile\x18\x02 \x03(\x0b\x32\x1e.PlusData.OBSOLETE_PlusProfile\x12!\n\x06person\x18\x03 \x03(\x0b\x32\x11.DocumentV2.DocV2\"\x17\n\x15\x46\x65\x61turedAppsContainer\"\x8d\x01\n\x0c\x43\x61llToAction\x12\x0c\n\x04type\x18\x01 \x01(\x05\x12\x12\n\nbuttonText\x18\x02 \x01(\t\x12!\n\nbuttonIcon\x18\x03 \x01(\x0b\x32\r.Common.Image\x12\x14\n\x0c\x64ismissalUrl\x18\x04 \x01(\t\x12\"\n\x04link\x18\x05 \x01(\x0b\x32\x14.DocAnnotations.Link\"A\n\x0cOverflowLink\x12\r\n\x05title\x18\x01 \x01(\t\x12\"\n\x04link\x18\x02 \x01(\x0b\x32\x14.DocAnnotations.Link\";\n\x16TrustedSourceContainer\x12!\n\x06source\x18\x01 \x01(\x0b\x32\x11.DocumentV2.DocV2\"v\n\"RecommendationsContainerWithHeader\x12&\n\x0bprimaryFace\x18\x01 \x01(\x0b\x32\x11.DocumentV2.DocV2\x12(\n\rsecondaryFace\x18\x03 \x03(\x0b\x32\x11.DocumentV2.DocV2\"\x19\n\x17RateAndSuggestContainer\"G\n\x16MoreByCreatorContainer\x12-\n\x12\x63reatorInformation\x18\x01 \x01(\x0b\x32\x11.DocumentV2.DocV2\"\xaf\x01\n\x0bPlusOneData\x12\x11\n\tsetByUser\x18\x01 \x01(\x08\x12\r\n\x05total\x18\x02 \x01(\x03\x12\x14\n\x0c\x63irclesTotal\x18\x03 \x01(\x03\x12?\n\x17oBSOLETECirclesProfiles\x18\x04 \x03(\x0b\x32\x1e.PlusData.OBSOLETE_PlusProfile\x12\'\n\x0c\x63irclePerson\x18\x05 \x03(\x0b\x32\x11.DocumentV2.DocV2B.\n com.google.android.finsky.protosB\nDocumentV2')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'document_v2_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  _globals['DESCRIPTOR']._options = None
  _globals['DESCRIPTOR']._serialized_options = b'\n com.google.android.finsky.protosB\nDocumentV2'
  _globals['_AVATARCARDCONTAINER']._serialized_start=198
  _globals['_AVATARCARDCONTAINER']._serialized_end=219
  _globals['_EMPTYCONTAINER']._serialized_start=221
  _globals['_EMPTYCONTAINER']._serialized_end=259
  _globals['_ARTISTCLUSTERCONTAINER']._serialized_start=261
  _globals['_ARTISTCLUSTERCONTAINER']._serialized_end=285
  _globals['_WIDECARDCONTAINER']._serialized_start=287
  _globals['_WIDECARDCONTAINER']._serialized_end=346
  _globals['_DISMISSAL']._serialized_start=348
  _globals['_DISMISSAL']._serialized_end=397
  _globals['_OBSOLETE_REASON']._serialized_start=399
  _globals['_OBSOLETE_REASON']._serialized_end=487
  _globals['_EDITORIALSERIESCONTAINER']._serialized_start=490
  _globals['_EDITORIALSERIESCONTAINER']._serialized_end=680
  _globals['_CONTAINERWITHBANNER']._serialized_start=682
  _globals['_CONTAINERWITHBANNER']._serialized_end=727
  _globals['_SERIESANTENNA']._serialized_start=730
  _globals['_SERIESANTENNA']._serialized_end=973
  _globals['_TEMPLATE']._serialized_start=976
  _globals['_TEMPLATE']._serialized_end=2940
  _globals['_VIDEOSNIPPET']._serialized_start=2942
  _globals['_VIDEOSNIPPET']._serialized_end=3022
  _globals['_WARMWELCOME']._serialized_start=3024
  _globals['_WARMWELCOME']._serialized_end=3079
  _globals['_ADDTOCIRCLESCONTAINER']._serialized_start=3081
  _globals['_ADDTOCIRCLESCONTAINER']._serialized_end=3104
  _globals['_DEALOFTHEDAY']._serialized_start=3106
  _globals['_DEALOFTHEDAY']._serialized_end=3168
  _globals['_ANNOTATIONS']._serialized_start=3171
  _globals['_ANNOTATIONS']._serialized_end=4877
  _globals['_PURCHASEHISTORYCONTAINER']._serialized_start=4879
  _globals['_PURCHASEHISTORYCONTAINER']._serialized_end=4905
  _globals['_RATECONTAINER']._serialized_start=4907
  _globals['_RATECONTAINER']._serialized_end=4922
  _globals['_REASONREVIEW']._serialized_start=4924
  _globals['_REASONREVIEW']._serialized_end=4974
  _globals['_SUGGESTIONREASONS']._serialized_start=4977
  _globals['_SUGGESTIONREASONS']._serialized_end=5131
  _globals['_DOCV2']._serialized_start=5134
  _globals['_DOCV2']._serialized_end=5990
  _globals['_REASON']._serialized_start=5993
  _globals['_REASON']._serialized_end=6222
  _globals['_SNOW']._serialized_start=6224
  _globals['_SNOW']._serialized_end=6289
  _globals['_SINGLECARDCONTAINER']._serialized_start=6291
  _globals['_SINGLECARDCONTAINER']._serialized_end=6312
  _globals['_NEXTBANNER']._serialized_start=6314
  _globals['_NEXTBANNER']._serialized_end=6382
  _globals['_ACTIONBANNER']._serialized_start=6385
  _globals['_ACTIONBANNER']._serialized_end=6523
  _globals['_REVIEW']._serialized_start=6526
  _globals['_REVIEW']._serialized_end=6955
  _globals['_MYCIRCLESCONTAINER']._serialized_start=6957
  _globals['_MYCIRCLESCONTAINER']._serialized_end=6977
  _globals['_BUNDLECONTAINER']._serialized_start=6979
  _globals['_BUNDLECONTAINER']._serialized_end=6996
  _globals['_BUNDLEBANNER']._serialized_start=6998
  _globals['_BUNDLEBANNER']._serialized_end=7054
  _globals['_RECOMMENDATIONSCONTAINER']._serialized_start=7056
  _globals['_RECOMMENDATIONSCONTAINER']._serialized_end=7082
  _globals['_TILETEMPLATE']._serialized_start=7084
  _globals['_TILETEMPLATE']._serialized_end=7145
  _globals['_REASONUSERACTION']._serialized_start=7147
  _globals['_REASONUSERACTION']._serialized_end=7234
  _globals['_VOUCHERINFO']._serialized_start=7236
  _globals['_VOUCHERINFO']._serialized_end=7311
  _globals['_MULTIROWCONTAINER']._serialized_start=7313
  _globals['_MULTIROWCONTAINER']._serialized_end=7350
  _globals['_REASONPLUSONE']._serialized_start=7353
  _globals['_REASONPLUSONE']._serialized_end=7498
  _globals['_FEATUREDAPPSCONTAINER']._serialized_start=7500
  _globals['_FEATUREDAPPSCONTAINER']._serialized_end=7523
  _globals['_CALLTOACTION']._serialized_start=7526
  _globals['_CALLTOACTION']._serialized_end=7667
  _globals['_OVERFLOWLINK']._serialized_start=7669
  _globals['_OVERFLOWLINK']._serialized_end=7734
  _globals['_TRUSTEDSOURCECONTAINER']._serialized_start=7736
  _globals['_TRUSTEDSOURCECONTAINER']._serialized_end=7795
  _globals['_RECOMMENDATIONSCONTAINERWITHHEADER']._serialized_start=7797
  _globals['_RECOMMENDATIONSCONTAINERWITHHEADER']._serialized_end=7915
  _globals['_RATEANDSUGGESTCONTAINER']._serialized_start=7917
  _globals['_RATEANDSUGGESTCONTAINER']._serialized_end=7942
  _globals['_MOREBYCREATORCONTAINER']._serialized_start=7944
  _globals['_MOREBYCREATORCONTAINER']._serialized_end=8015
  _globals['_PLUSONEDATA']._serialized_start=8018
  _globals['_PLUSONEDATA']._serialized_end=8193
# @@protoc_insertion_point(module_scope)
