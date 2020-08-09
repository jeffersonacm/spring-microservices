package academy.devdojo.youtube.course.endpoint.repository;

import academy.devdojo.youtube.course.endpoint.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {
}