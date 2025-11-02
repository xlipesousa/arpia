from __future__ import annotations

from rest_framework.pagination import CursorPagination


class HuntFindingPagination(CursorPagination):
    page_size = 25
    ordering = "-last_profiled_at"
    page_size_query_param = "page_size"
    max_page_size = 100


class HuntRecommendationPagination(CursorPagination):
    page_size = 50
    ordering = "-updated_at"
    page_size_query_param = "page_size"
    max_page_size = 100


class HuntTechniquePagination(CursorPagination):
    page_size = 40
    ordering = "id"
    page_size_query_param = "page_size"
    max_page_size = 200
